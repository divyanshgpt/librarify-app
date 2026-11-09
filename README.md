# Librarify: Library Management System

A web-based library management system built with **plain Python and SQLite**, with no frameworks and no packages to install. Librarians manage the catalog, members and loans. Members browse books, track what they have borrowed, and recover their own passwords.

> Built as a first-year computer science project. Only Python's standard library is used on the server, and the page is plain HTML, CSS and JavaScript.

## Screenshots

**Book Catalog**
<img width="1920" height="1080" alt="catalog" src="https://github.com/user-attachments/assets/de5e74e5-238c-48d3-8abd-fae9d34f6f3e" />
**Overview**
<img width="1912" height="912" alt="overview" src="https://github.com/user-attachments/assets/01c4d6e9-a277-49ad-a5d1-41c55c2498a5" />




## Features

**For librarians**

* **Overview:** library statistics, most borrowed books, popular category, top reader, a reading fact of the day, and book news
* **Book catalog:** add, edit and delete books; issue and return them; search by title, author or ID; filter by category and status
* **Members:** add members, reset their passwords, remove them
* **Borrow & return:** see what is out, what is overdue, and the full history
* **Dashboard strip:** books, loans, books due today and active members at a glance

**For members**

* **Sign up** with a security question
* **Overview:** the reading fact of the day, most borrowed, popular category, top reader and book news
* **Book catalog:** browse and search, and see which books are available
* **My books:** what you have borrowed, due dates and any fine

**For everyone**

* **Forgot password:** answer your security question to set a new password
* **Show / hide** button on every password box
* **Notifications:** a bell that shows overdue books and books due in the next 3 days
* **Search** from the top bar (Ctrl + K or Cmd + K to focus it)
* **Responsive layout** that works on a phone-sized screen

## Library rules

|Rule|Value|
|-|-|
|Loan period|14 days|
|Books per member|3 at a time|
|Late fee|Rs. 200 flat fee, plus Rs. 10 for each late day|

These are constants at the top of `database.py` and are easy to change.

## Getting started

### Requirements

* **Python 3.9 or newer**. Nothing else needs installing.
* An internet connection is optional. It is only used for the book news and the web fonts.

### Run it

1. Put `library_web.py`, `database.py` and `index.html` in **one folder**.
2. Open a terminal in that folder.
3. Start the server:

    ```bash
    python library_web.py
    ```

    Use `python3` on Mac or Linux. Add `--demo` the first time to load sample books and members:

    ```bash
    python library_web.py --demo
    ```

4. Your browser opens at **http://localhost:8000**. If it doesn't, open that address yourself.
5. Press `Ctrl + C` in the terminal to stop the server if you want.

### Log in (pre-defined users for demo use)

|Role|Username|Password|
|-|-|-|
|Librarian|`admin`|`admin123`|
|Member (demo)|`asha01`|`asha123`|
|Member (demo)|`ravi02`|`ravi123`|

The member accounts exist only if you started with `--demo`.

The demo security answers are `Dune` for `asha01` and `Jaipur` for `ravi02`.

### Start fresh

Stop the server and delete the `library.db` file. A new, empty database is created the next time you run it.

## How it works

```
 Browser (index.html)
   |  JSON over HTTP:  POST /api/<action>
   v
 library_web.py   (web server: sessions, who is allowed to do what)
   |
   v
 database.py      (all library rules and all SQL)
   |
   v
 library.db       (SQLite file, created automatically)
```

* **`index.html`** is the whole front end. It draws every page in the browser and talks to the server with `fetch`.
* **`library_web.py`** is a small server built on `http.server`. Every action is listed in one table (`ACTIONS`) with the lowest role allowed to use it: public, member or librarian.
* **`database.py`** holds the rules: fines, the 3-book limit, password rules, the security question, and statistics. The server never writes SQL.

### Database tables

|Table|Holds|
|-|-|
|`users`|librarians and members, with hashed passwords and hashed security answers|
|`books`|the catalog: ID, title, author, category|
|`loans`|who borrowed which book, due date, return date and fine|

## Security

* Passwords and security answers are stored as **salted PBKDF2-SHA256 hashes** (200,000 rounds). The real values are never saved.
* Every database query uses **parameters**, so typed text can't change the SQL.
* Role checks happen on the **server**. A member who calls a librarian-only action gets a 403 error.
* The login cookie is `HttpOnly` and `SameSite=Strict`.
* Forgot-password answers are limited to **5 wrong tries per 15 minutes**. A correct reset logs that account out on every device.
* Members see other readers only as a first name and initial (for example, "Asha S.") and never see who holds a borrowed book.

### Known limits

* It runs on `localhost` over plain HTTP. For real use it would need HTTPS and a production server.
* Login sessions are kept in memory, so everyone is logged out when the server restarts.
* Wrong login passwords are not rate-limited (only the password recovery is).
* Security questions are only as strong as the answers people choose.

## Project structure

```
.
├── index.html       front end (HTML, CSS, JavaScript)
├── library_web.py   web server and API
├── database.py      library rules and SQLite
└── library.db       created automatically on the first run
```

## Customising

|To change...|Edit|
|-|-|
|Loan days, fees, book limit|the constants at the top of `database.py`|
|Port number|`PORT` in `library_web.py`|
|News sources|`NEWS_FEEDS` in `library_web.py` (any RSS address)|
|Reading facts|the `FACTS` list in `library_web.py`|
|Sidebar quotes|the `QUOTES` list in `index.html`|
|Colours|the variables at the top of the `<style>` block in `index.html`|

## What I learned

Building Librarify taught me a lot more than the syntax of a language. These are the biggest lessons.

**Python and its standard library**

* A complete application can be built with no outside packages. I used `sqlite3`, `http.server`, `json`, `hashlib`, `hmac`, `secrets`, `datetime`, `urllib` and `xml.etree`, each one for a single clear job.
* Dictionaries are powerful. The `ACTIONS` table maps every action name to its function and the lowest role allowed to run it, which replaced a long chain of `if` statements.
* Context managers (`with`) make sure files and database connections are always closed, even when something goes wrong.
* Custom exceptions (`LibraryError`) separate "the user did something wrong" from "the program has a bug", so each one can be handled and explained properly.

**SQLite and databases**

* Designing tables, linking them with foreign keys (`users`, `books`, `loans`), and reading them back together with `JOIN`s.
* Always passing values as **parameters** (`?`) instead of building SQL from text, which stops SQL injection.
* A partial unique index lets the database itself refuse to lend one book to two people at the same time.
* Transactions: a change is saved only if every step succeeds, and is rolled back otherwise.
* Upgrading an existing database safely with `ALTER TABLE`, so old data keeps working when new features arrive.

**How a Python web server works**

* A browser sends an HTTP request, the server runs some code, and it sends back a response with a status code: 200 (OK), 400 (bad request), 401 (not logged in), 403 (not allowed) or 404 (not found).
* The page and the server talk using **JSON**. The page calls `fetch("/api/...")` and the server replies with data, not a finished page.
* Cookies and sessions: after login the server hands out a random session ID, and the browser sends it back with every request so the server knows who is asking.
* A threaded server (`ThreadingHTTPServer`) can handle several users at the same time.
* The browser can never be trusted, so every action is checked against the user's role on the server, not just hidden in the page.

**Security**

* Hashing is not encryption. Passwords and security answers are stored as salted PBKDF2 hashes, so nobody can read them, not even me.
* Comparing secrets safely with `hmac.compare_digest`, and locking password recovery after 5 wrong answers.
* Thinking about what each role should be allowed to see, for example showing other readers only as "Asha S."

**The front end**

* Building a whole interface with plain JavaScript: the DOM, events, `fetch`, and redrawing the screen from data.
* Responsive layouts with CSS grid, and keeping colours and fonts consistent with CSS variables.
* Small details that make an app pleasant: keyboard shortcuts, helpful error messages, labels for screen readers and a show/hide password button.

**Software design and good habits**

* Splitting the project into three layers (the page, the server and the database rules) so each one can change without breaking the others.
* Showing friendly messages instead of letting the program crash.
* Testing the awkward cases on purpose: duplicate IDs, wrong answers, locked accounts, and books that are already issued.
* Reading error messages carefully and debugging one step at a time.

## Ideas for the future

* Book reservations and a waiting list
* Renewing a loan
* Email or SMS reminders for due dates
* Book cover images and ISBN lookup
* Export reports to CSV or PDF
* Move to a framework such as Flask with HTTPS

## Credits

Built by **Divyansh Gupta**

* GitHub: [divyanshgpt](https://github.com/divyanshgpt)
* LinkedIn: [divyansh-gpt](https://www.linkedin.com/in/divyansh-gpt)
