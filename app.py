from flask import Flask, render_template, request, redirect, url_for, session, flash
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
    return render_template('signup.html', show_sidebar=False)

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
            session['username'] = user['username'] 
            return redirect(url_for('dashboard'))

        return "Invalid credentials. Please try again."
    return render_template('login.html', show_sidebar=False)

# Dashboard Route
@app.route('/dashboard')


def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    
    user_id = session['user_id']
    username = session.get('username')  # Retrieve the username from the session

    conn = get_db_connection()
    transactions = conn.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC LIMIT 5", (session['user_id'],)).fetchall()
    total_income = conn.execute("SELECT SUM(amount) FROM transactions WHERE user_id = ? AND type = 'income'", (session['user_id'],)).fetchone()[0] or 0
    total_expense = conn.execute("SELECT SUM(amount) FROM transactions WHERE user_id = ? AND type = 'expense'", (session['user_id'],)).fetchone()[0] or 0
    total_balance = total_income - total_expense
    conn.close()

    return render_template('dashboard.html',username=session.get('username', 'User'), transactions=transactions, total_income=total_income, total_expense=total_expense, total_balance=total_balance, show_sidebar=True)




    # Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user:
            # Redirect to a route where the user can answer their security question
            return redirect(url_for('security_question', username=username))
        else:
            flash("Username not found. Please try again.")
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

# Security Question Route
@app.route('/security_question/<username>', methods=['GET', 'POST'])
def security_question(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not user:
        flash("User not found. Please try again.")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        answer = request.form['security_answer']
        if user['security_answer'].lower() == answer.lower():
            # Redirect to reset password page if the answer is correct
            return redirect(url_for('reset_password', username=username))
        else:
            flash("Incorrect answer. Please try again.")
            return redirect(url_for('security_question', username=username))

    # Pass the security question to the template
    return render_template('security_question.html', username=username, security_question=user['security_question'])


# Reset Password Route
@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password)
        
        conn = get_db_connection()
        conn.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        conn.close()

        flash("Password has been reset successfully. You can now log in.")
        return redirect(url_for('home'))

    return render_template('reset_password.html', username=username)

@app.route('/view_transactions', methods=['GET'])
def view_transactions():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    user_id = session['user_id']
    year = request.args.get('year')
    month = request.args.get('month')
    transaction_type = request.args.get('type')

    # Build the base SQL query
    query = "SELECT * FROM transactions WHERE user_id = ?"
    params = [user_id]

    # Add conditions for year, month, and type if specified
    if year:
        query += " AND strftime('%Y', date) = ?"
        params.append(year)
    if month:
        query += " AND strftime('%m', date) = ?"
        params.append(month)
    if transaction_type:
        query += " AND type = ?"
        params.append(transaction_type)

    query += " ORDER BY date DESC"

    # Execute the query with the parameters
    conn = get_db_connection()
    transactions = conn.execute(query, params).fetchall()
    conn.close()

    return render_template('view_transactions.html', transactions=transactions, show_sidebar=True)


@app.route('/add_expense', methods=['GET', 'POST'])
def add_expense():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        amount = request.form['amount']
        category = request.form['category']
        date = request.form['date']  # Get the date from the form
        description = request.form['description']
        user_id = session['user_id']

        # Insert the expense into the database
        conn = get_db_connection()
        conn.execute("INSERT INTO transactions (user_id, type, category, amount, date, description) VALUES (?, 'expense', ?, ?, ?, ?)",
                     (user_id, category, amount, date, description))
        conn.commit()
        conn.close()

        # Redirect to the dashboard or a success page
        return redirect(url_for('dashboard'))

    return render_template('add_expense.html', show_sidebar=True)


@app.route('/add_income', methods=['GET', 'POST'])
def add_income():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        amount = request.form['amount']
        category = request.form['category']
        date = request.form['date']  # Get the date from the form
        description = request.form['description']
        user_id = session['user_id']

        # Insert the income into the database
        conn = get_db_connection()
        conn.execute("INSERT INTO transactions (user_id, type, category, amount, date, description) VALUES (?, 'income', ?, ?, ?, ?)",
                     (user_id, category, amount, date, description))
        conn.commit()
        conn.close()

        # Redirect to the dashboard or a success page
        return redirect(url_for('dashboard'))

    return render_template('add_income.html', show_sidebar=True)




if __name__ == '__main__':
    app.run(debug=True)