"""
BACKEND for the Library Management System.

Everything that touches the database lives in this file. The GUI (library_gui.py)
never writes SQL; it only calls the functions below.

Tables
  users  - librarians and members (passwords and security answers are stored as salted hashes)
  books  - the book records
  loans  - who borrowed which book, when it is due, when it came back, any fine

When a rule is broken (wrong password, book already issued, ...) the functions
raise LibraryError with a readable message. The GUI shows that message.
"""

import hashlib
import hmac
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import date, timedelta

DB_FILE = "library.db"
LOAN_DAYS = 14          # days a book can be kept
LATE_FLAT_FEE = 200     # rupees charged as soon as a book is returned late
FINE_PER_DAY = 10       # extra rupees for every late day
MAX_BOOKS = 3           # most books one member can hold at a time
HASH_ROUNDS = 200_000   # makes password guessing slow
RECOVERY_MAX_TRIES = 5          # wrong answers allowed to the security question...
RECOVERY_LOCK_SECONDS = 900     # ...within this many seconds (15 minutes)


class LibraryError(Exception):
    """A problem the user can understand and fix (not a program bug)."""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------
@contextmanager
def db():
    """Open the database, save the changes if all went well, always close it."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row            # lets us use row["title"]
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def today():
    return date.today().isoformat()


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------
def hash_password(password, salt_hex):
    """Turn a password into an unreadable hash. Same password + same salt = same hash."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), HASH_ROUNDS
    ).hex()


def new_credentials(password):
    salt = os.urandom(16).hex()               # a random salt for every user
    return salt, hash_password(password, salt)


def check_password_rules(password):
    if len(password) < 6:
        raise LibraryError("Password must be at least 6 characters.")


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def init_db():
    """Create the tables on first run, plus a default librarian account."""
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL UNIQUE,
                name       TEXT NOT NULL,
                phone      TEXT,
                role       TEXT NOT NULL CHECK (role IN ('librarian', 'member')),
                salt       TEXT NOT NULL,
                pwd_hash   TEXT NOT NULL,
                active     INTEGER NOT NULL DEFAULT 1,
                created_on TEXT NOT NULL,
                security_question TEXT,
                answer_salt       TEXT,
                answer_hash       TEXT
            );

            CREATE TABLE IF NOT EXISTS books (
                book_id  TEXT PRIMARY KEY,
                title    TEXT NOT NULL,
                author   TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'General'
            );

            CREATE TABLE IF NOT EXISTS loans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                book_id     TEXT NOT NULL REFERENCES books(book_id) ON DELETE CASCADE,
                user_id     INTEGER NOT NULL REFERENCES users(id),
                issue_date  TEXT NOT NULL,
                due_date    TEXT NOT NULL,
                return_date TEXT,
                fine        INTEGER NOT NULL DEFAULT 0
            );

            -- the database itself refuses to issue one book to two people
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_loan_per_book
                ON loans(book_id) WHERE return_date IS NULL;
            """
        )
        # databases made before the security question existed get the new columns
        have = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        for column in ("security_question", "answer_salt", "answer_hash"):
            if column not in have:
                conn.execute(f"ALTER TABLE users ADD COLUMN {column} TEXT")
        has_librarian = conn.execute(
            "SELECT 1 FROM users WHERE role = 'librarian'"
        ).fetchone()
        if not has_librarian:
            salt, pwd_hash = new_credentials("admin123")
            conn.execute(
                "INSERT INTO users (username, name, phone, role, salt, pwd_hash, created_on) "
                "VALUES ('admin', 'Librarian', '', 'librarian', ?, ?, ?)",
                (salt, pwd_hash, today()),
            )


def default_password_unchanged():
    """True while the first-run librarian account still uses admin / admin123."""
    return authenticate("admin", "admin123") is not None


# ---------------------------------------------------------------------------
# Users: login, sign-up, passwords
# ---------------------------------------------------------------------------
def authenticate(username, password):
    """Return the user (as a dict) if the login is correct, otherwise None."""
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (username.strip().lower(),),
        ).fetchone()
    if row is None:
        return None
    attempt = hash_password(password, row["salt"])
    if hmac.compare_digest(attempt, row["pwd_hash"]):     # safe comparison
        return dict(row)
    return None


def create_user(username, password, name, phone, role="member", question="", answer=""):
    username = username.strip().lower()
    name = name.strip()
    phone = phone.strip()
    if not re.fullmatch(r"[a-z0-9_]{3,20}", username):
        raise LibraryError("Username: 3-20 letters, digits or underscore only.")
    if not name:
        raise LibraryError("Name cannot be empty.")
    if role == "member" and not (phone.isdigit() and len(phone) == 10):
        raise LibraryError("Phone must be exactly 10 digits.")
    check_password_rules(password)
    salt, pwd_hash = new_credentials(password)
    question, answer_salt, answer_hash = secret_answer(question, answer)
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO users (username, name, phone, role, salt, pwd_hash, created_on, "
                "security_question, answer_salt, answer_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (username, name, phone, role, salt, pwd_hash, today(),
                 question, answer_salt, answer_hash),
            )
    except sqlite3.IntegrityError:
        raise LibraryError("That username is already taken.")


def change_password(user_id, current, new):
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None or not hmac.compare_digest(
            hash_password(current, row["salt"]), row["pwd_hash"]
        ):
            raise LibraryError("Current password is wrong.")
        check_password_rules(new)
        salt, pwd_hash = new_credentials(new)
        conn.execute(
            "UPDATE users SET salt = ?, pwd_hash = ? WHERE id = ?", (salt, pwd_hash, user_id)
        )


def reset_password(user_id, new):
    """Librarian sets a new password for a member who forgot theirs."""
    check_password_rules(new)
    salt, pwd_hash = new_credentials(new)
    with db() as conn:
        conn.execute(
            "UPDATE users SET salt = ?, pwd_hash = ? WHERE id = ? AND role = 'member'",
            (salt, pwd_hash, user_id),
        )


# ---------------------------------------------------------------------------
# Forgotten passwords: a security question chosen by the user
# ---------------------------------------------------------------------------
_wrong_answers = {}        # username -> times of recent wrong answers (kept in memory)


def clean_answer(answer):
    """'  Delhi  Public ' and 'delhi public' count as the same answer."""
    return " ".join(answer.lower().split())


def secret_answer(question, answer):
    """
    Check a security question and its answer.
    Returns (question, salt, hash), or (None, None, None) if both were left blank.
    The answer is hashed just like a password, so nobody can read it from the database.
    """
    question = question.strip()
    if not question and not answer.strip():
        return None, None, None
    if not 8 <= len(question) <= 120:
        raise LibraryError("Security question: 8 to 120 characters.")
    if len(clean_answer(answer)) < 3:
        raise LibraryError("Security answer: at least 3 characters.")
    salt, answer_hash = new_credentials(clean_answer(answer))
    return question, salt, answer_hash


def has_security_question(user_id):
    with db() as conn:
        row = conn.execute(
            "SELECT security_question FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return bool(row and row["security_question"])


def set_security_question(user_id, password, question, answer):
    """Set or replace the question. Needs the current password, so a borrowed session can't change it."""
    question, answer_salt, answer_hash = secret_answer(question, answer)
    if question is None:
        raise LibraryError("Please enter both a question and an answer.")
    with db() as conn:
        row = conn.execute(
            "SELECT salt, pwd_hash FROM users WHERE id = ? AND active = 1", (user_id,)
        ).fetchone()
        if row is None or not hmac.compare_digest(
            hash_password(password, row["salt"]), row["pwd_hash"]
        ):
            raise LibraryError("Current password is wrong.")
        conn.execute(
            "UPDATE users SET security_question = ?, answer_salt = ?, answer_hash = ? WHERE id = ?",
            (question, answer_salt, answer_hash, user_id),
        )


def get_security_question(username):
    """Step 1 of 'forgot password': show the person their own question."""
    with db() as conn:
        row = conn.execute(
            "SELECT security_question FROM users WHERE username = ? AND active = 1",
            (username.strip().lower(),),
        ).fetchone()
    if row is None:
        raise LibraryError("No account found with that username.")
    if not row["security_question"]:
        raise LibraryError("This account has no security question. "
                           "Members can ask the librarian to reset their password.")
    return row["security_question"]


def _too_many_wrong_answers(username):
    now = time.time()
    recent = [t for t in _wrong_answers.get(username, []) if now - t < RECOVERY_LOCK_SECONDS]
    _wrong_answers[username] = recent
    return len(recent) >= RECOVERY_MAX_TRIES


def recover_password(username, answer, new_password):
    """
    Step 2 of 'forgot password': the right answer sets a new password.
    After RECOVERY_MAX_TRIES wrong answers the account is locked for a while,
    so nobody can sit and guess. Returns the user's id.
    """
    username = username.strip().lower()
    check_password_rules(new_password)
    if _too_many_wrong_answers(username):
        raise LibraryError("Too many wrong answers. Please try again in 15 minutes.")
    with db() as conn:
        row = conn.execute(
            "SELECT id, answer_salt, answer_hash FROM users WHERE username = ? AND active = 1",
            (username,),
        ).fetchone()
        correct = (
            row is not None and row["answer_hash"] is not None
            and hmac.compare_digest(
                hash_password(clean_answer(answer), row["answer_salt"]), row["answer_hash"])
        )
        if correct:
            salt, pwd_hash = new_credentials(new_password)
            conn.execute(
                "UPDATE users SET salt = ?, pwd_hash = ? WHERE id = ?", (salt, pwd_hash, row["id"])
            )
            _wrong_answers.pop(username, None)
            return row["id"]
    _wrong_answers.setdefault(username, []).append(time.time())
    left = RECOVERY_MAX_TRIES - len(_wrong_answers[username])
    if left > 0:
        raise LibraryError(f"That answer is not correct. {left} attempt(s) left.")
    raise LibraryError("That answer is not correct. Too many tries, please wait 15 minutes.")


def list_members():
    with db() as conn:
        rows = conn.execute(
            """
            SELECT u.id, u.username, u.name, u.phone, u.created_on,
                   (SELECT COUNT(*) FROM loans l
                     WHERE l.user_id = u.id AND l.return_date IS NULL) AS held
            FROM users u
            WHERE u.role = 'member' AND u.active = 1
            ORDER BY u.name
            """
        ).fetchall()
    return [dict(r) for r in rows]


def remove_member(user_id):
    """Deactivate (not delete), so old loan records still make sense."""
    with db() as conn:
        held = conn.execute(
            "SELECT COUNT(*) FROM loans WHERE user_id = ? AND return_date IS NULL", (user_id,)
        ).fetchone()[0]
        if held:
            raise LibraryError("This member still has books. Return them first.")
        conn.execute(
            "UPDATE users SET active = 0 WHERE id = ? AND role = 'member'", (user_id,)
        )


# ---------------------------------------------------------------------------
# Books
# ---------------------------------------------------------------------------
def add_book(book_id, title, author, category):
    book_id, title, author = book_id.strip(), title.strip(), author.strip()
    category = category.strip().title() or "General"
    if not book_id or not title or not author:
        raise LibraryError("Book ID, title and author are required.")
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO books (book_id, title, author, category) VALUES (?, ?, ?, ?)",
                (book_id, title, author, category),
            )
    except sqlite3.IntegrityError:
        raise LibraryError("That Book ID already exists.")


def get_book(book_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM books WHERE book_id = ?", (book_id,)).fetchone()
    if row is None:
        raise LibraryError("Book not found.")
    return dict(row)


def update_book(book_id, title, author, category):
    title, author = title.strip(), author.strip()
    category = category.strip().title() or "General"
    if not title or not author:
        raise LibraryError("Title and author are required.")
    with db() as conn:
        conn.execute(
            "UPDATE books SET title = ?, author = ?, category = ? WHERE book_id = ?",
            (title, author, category, book_id),
        )


def delete_book(book_id):
    """Remove a book. Its old loan history goes with it."""
    with db() as conn:
        issued = conn.execute(
            "SELECT 1 FROM loans WHERE book_id = ? AND return_date IS NULL", (book_id,)
        ).fetchone()
        if issued:
            raise LibraryError("Can't delete a book that is currently issued.")
        conn.execute("DELETE FROM books WHERE book_id = ?", (book_id,))


def list_categories():
    with db() as conn:
        rows = conn.execute("SELECT DISTINCT category FROM books ORDER BY category").fetchall()
    return [r["category"] for r in rows]


def list_books(search="", category="All"):
    """Books with their current holder (if issued). Optional search and category filter."""
    like = f"%{search.strip()}%"
    sql = """
        SELECT b.book_id, b.title, b.author, b.category,
               l.due_date,
               u.id AS holder_id, u.username AS holder_username, u.name AS holder_name
        FROM books b
        LEFT JOIN loans l ON l.book_id = b.book_id AND l.return_date IS NULL
        LEFT JOIN users u ON u.id = l.user_id
        WHERE (b.title LIKE ? OR b.author LIKE ? OR b.book_id LIKE ?)
    """
    params = [like, like, like]
    if category and category != "All":
        sql += " AND b.category = ?"
        params.append(category)
    sql += " ORDER BY b.title"
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Issue / return
# ---------------------------------------------------------------------------
def late_days_for(due_date, end_date=None):
    end = date.fromisoformat(end_date) if end_date else date.today()
    return max(0, (end - date.fromisoformat(due_date)).days)


def fine_for(due_date, end_date=None):
    """0 if on time. Otherwise a flat fee plus a charge for every late day."""
    late = late_days_for(due_date, end_date)
    return LATE_FLAT_FEE + late * FINE_PER_DAY if late else 0


def issue_book(book_id, username):
    """Lend a book to a member. Returns the due date."""
    username = username.strip().lower()
    with db() as conn:
        if conn.execute("SELECT 1 FROM books WHERE book_id = ?", (book_id,)).fetchone() is None:
            raise LibraryError("Book not found.")
        member = conn.execute(
            "SELECT id, name FROM users WHERE username = ? AND role = 'member' AND active = 1",
            (username,),
        ).fetchone()
        if member is None:
            raise LibraryError("Member not found. Check the username.")
        if conn.execute(
            "SELECT 1 FROM loans WHERE book_id = ? AND return_date IS NULL", (book_id,)
        ).fetchone():
            raise LibraryError("This book is already issued.")
        held = conn.execute(
            "SELECT COUNT(*) FROM loans WHERE user_id = ? AND return_date IS NULL",
            (member["id"],),
        ).fetchone()[0]
        if held >= MAX_BOOKS:
            raise LibraryError(f"{member['name']} already has {MAX_BOOKS} books (the limit).")
        due = (date.today() + timedelta(days=LOAN_DAYS)).isoformat()
        conn.execute(
            "INSERT INTO loans (book_id, user_id, issue_date, due_date) VALUES (?, ?, ?, ?)",
            (book_id, member["id"], today(), due),
        )
    return due


def return_book(book_id):
    """Take a book back. Returns {'late_days': n, 'fine': rupees}."""
    with db() as conn:
        loan = conn.execute(
            "SELECT * FROM loans WHERE book_id = ? AND return_date IS NULL", (book_id,)
        ).fetchone()
        if loan is None:
            raise LibraryError("This book is not issued.")
        fine = fine_for(loan["due_date"])
        late_days = late_days_for(loan["due_date"])
        conn.execute(
            "UPDATE loans SET return_date = ?, fine = ? WHERE id = ?", (today(), fine, loan["id"])
        )
    return {"late_days": late_days, "fine": fine}


def loans(user_id=None, mode="active"):
    """
    Loan records, newest first.
      user_id : only this member's loans (None = everyone's)
      mode    : 'active' (still out), 'overdue' (out and late) or 'all' (full history)
    Each record has a ready-to-show 'status' and 'fine'.
    """
    sql = """
        SELECT l.*, b.title, u.username, u.name
        FROM loans l
        JOIN books b ON b.book_id = l.book_id
        JOIN users u ON u.id = l.user_id
        WHERE 1 = 1
    """
    params = []
    if user_id is not None:
        sql += " AND l.user_id = ?"
        params.append(user_id)
    if mode in ("active", "overdue"):
        sql += " AND l.return_date IS NULL"
    if mode == "overdue":
        sql += " AND l.due_date < ?"
        params.append(today())
    sql += " ORDER BY l.issue_date DESC, l.id DESC"
    with db() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    for r in rows:
        if r["return_date"]:
            r["status"] = "Returned"
        else:
            r["fine"] = fine_for(r["due_date"])          # fine so far
            late = late_days_for(r["due_date"])
            r["status"] = f"Overdue by {late} day(s)" if late else "On time"
    return rows


def stats():
    with db() as conn:
        return {
            "books": conn.execute("SELECT COUNT(*) FROM books").fetchone()[0],
            "issued": conn.execute(
                "SELECT COUNT(*) FROM loans WHERE return_date IS NULL").fetchone()[0],
            "overdue": conn.execute(
                "SELECT COUNT(*) FROM loans WHERE return_date IS NULL AND due_date < ?",
                (today(),)).fetchone()[0],
            "members": conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'member' AND active = 1").fetchone()[0],
        }


def insights():
    """Extra facts for the librarian overview. Every part is safe on an empty library."""
    t = today()
    soon = (date.today() + timedelta(days=3)).isoformat()
    month_start = date.today().replace(day=1).isoformat()
    with db() as conn:
        popular_books = [dict(r) for r in conn.execute(
            """SELECT b.title, b.author, COUNT(*) AS times
               FROM loans l JOIN books b ON b.book_id = l.book_id
               GROUP BY b.book_id ORDER BY times DESC, b.title LIMIT 3""").fetchall()]
        top_cat = conn.execute(
            """SELECT b.category, COUNT(*) AS times
               FROM loans l JOIN books b ON b.book_id = l.book_id
               GROUP BY b.category ORDER BY times DESC, b.category LIMIT 1""").fetchone()
        top_reader = conn.execute(
            """SELECT u.name, COUNT(*) AS times
               FROM loans l JOIN users u ON u.id = l.user_id
               GROUP BY u.id ORDER BY times DESC, u.name LIMIT 1""").fetchone()
        due_soon = [dict(r) for r in conn.execute(
            """SELECT b.title, u.name, l.due_date
               FROM loans l JOIN books b ON b.book_id = l.book_id
               JOIN users u ON u.id = l.user_id
               WHERE l.return_date IS NULL AND l.due_date >= ? AND l.due_date <= ?
               ORDER BY l.due_date""", (t, soon)).fetchall()]
        never_borrowed = conn.execute(
            """SELECT COUNT(*) FROM books b
               WHERE NOT EXISTS (SELECT 1 FROM loans l WHERE l.book_id = b.book_id)""").fetchone()[0]
        fines = conn.execute(
            "SELECT COALESCE(SUM(fine), 0) FROM loans WHERE return_date IS NOT NULL").fetchone()[0]
        month_loans = conn.execute(
            "SELECT COUNT(*) FROM loans WHERE issue_date >= ?", (month_start,)).fetchone()[0]
        total_books = conn.execute("SELECT COUNT(*) FROM books").fetchone()[0]
        issued = conn.execute(
            "SELECT COUNT(*) FROM loans WHERE return_date IS NULL").fetchone()[0]
    return {
        "popular_books": popular_books,
        "top_category": dict(top_cat) if top_cat else None,
        "top_reader": dict(top_reader) if top_reader else None,
        "due_soon": due_soon,
        "never_borrowed": never_borrowed,
        "fines_collected": fines,
        "loans_this_month": month_loans,
        "in_use_percent": round(100 * issued / total_books) if total_books else 0,
    }


# ---------------------------------------------------------------------------
# Demo data (python library_gui.py --demo)
# ---------------------------------------------------------------------------
def seed_demo():
    books = [
        ("001", "Starting Out with Python", "Tony Gaddis", "Programming"),
        ("002", "Mathematics for Computing", "David C", "Mathematics"),
        ("003", "Clean Code", "Robert Martin", "Programming"),
        ("004", "Wings of Fire", "APJ Abdul Kalam", "Biography"),
        ("005", "Discrete Mathematics", "Kenneth Rosen", "Mathematics"),
    ]
    for b in books:
        try:
            add_book(*b)
        except LibraryError:
            pass                                   # already there
    try:
        create_user("asha01", "asha123", "Asha Sharma", "9876543210",
                    question="What is your favourite book?", answer="Dune")
        create_user("ravi02", "ravi123", "Ravi Kumar", "9123456789",
                    question="In which city were you born?", answer="Jaipur")
    except LibraryError:
        pass
