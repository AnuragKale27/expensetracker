from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
from flask import Response
import csv


from functools import wraps

from flask import make_response

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database connection
def get_db_connection():
    conn = sqlite3.connect('database/expense_tracker.db')
    conn.row_factory = sqlite3.Row
    return conn

# Home/Login Route
@app.route('/')
def home():
    return render_template('login.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password, security_question, security_answer) VALUES (?, ?, ?, ?)",
                         (username, password, security_question, security_answer))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists. Please choose a different one."
        finally:
            conn.close()

        return redirect(url_for('home'))
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))

        return "Invalid credentials. Please try again."
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')


def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    conn = get_db_connection()
    transactions = conn.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT 5", (session['user_id'],)).fetchall()
    total_income = conn.execute("SELECT SUM(amount) FROM transactions WHERE user_id = ? AND type = 'income'", (session['user_id'],)).fetchone()[0] or 0
    total_expense = conn.execute("SELECT SUM(amount) FROM transactions WHERE user_id = ? AND type = 'expense'", (session['user_id'],)).fetchone()[0] or 0
    total_balance = total_income - total_expense
    conn.close()

    return render_template('dashboard.html', transactions=transactions, total_income=total_income, total_expense=total_expense, total_balance=total_balance)

if __name__ == '__main__':
    app.run(debug=True)
