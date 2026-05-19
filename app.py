from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- DATABASE SETUP ---------------- #

def create_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

create_database()

# ---------------- HOME ---------------- #

@app.route('/')
def home():
    return redirect('/login')

# ---------------- REGISTER ---------------- #

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Basic validation
        if username == "" or password == "":
            return "Username and Password cannot be empty"

        # Hash password
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            return redirect('/login')

        except sqlite3.IntegrityError:
            return "User already exists!"

    return render_template('register.html')

# ---------------- LOGIN ---------------- #

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username'].strip()
        password = request.form['password'].strip()

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user:

            stored_password = user[2]

            # Verify password
            if bcrypt.checkpw(
                password.encode('utf-8'),
                stored_password.encode('utf-8')
            ):

                session['user'] = username
                return redirect('/dashboard')

        return "Invalid Username or Password"

    return render_template('login.html')

# ---------------- DASHBOARD ---------------- #

@app.route('/dashboard')
def dashboard():

    if 'user' in session:
        return render_template(
            'dashboard.html',
            username=session['user']
        )

    return redirect('/login')

# ---------------- LOGOUT ---------------- #

@app.route('/logout')
def logout():

    session.pop('user', None)

    return redirect('/login')

# ---------------- RUN APP ---------------- #

if __name__ == '__main__':
    app.run(debug=True)