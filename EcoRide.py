from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import bcrypt
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# MySQL Configuration
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'harshini_24706'
app.config['MYSQL_DB'] = 'ecoride'
mysql = MySQL(app)

@app.route('/')
def signup():
    return render_template('LoginSignup.html')

@app.route('/signup_page', methods=['POST'])
def signup_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('psw')
        if not username or not email or not password:
            flash('All fields are required.')
            return redirect(url_for('Index.html'))

        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            if user:
                flash('Email already in use.')
                return redirect(url_for('Index.html'))

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur.execute("INSERT INTO users (email, password, username) VALUES (%s, %s, %s)", (email, hashed_password, username))
            mysql.connection.commit()
            cur.close()
            flash('User created successfully.')
            return render_template('Index.html')
        except Exception as e:
            print("Error executing query:", e)
            flash('Error executing query.')
            return redirect(url_for('Index.html'))

@app.route('/login_page', methods=['POST'])
def login_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('psw')

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('Index.html'))

        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT password FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user:
                flash('Invalid username or password.')
                return redirect(url_for('Index.html'))

            hashed_password_bytes = user[0].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password_bytes):
                flash('Logged in successfully.')
                session['username'] = username # Store username in session
                return redirect(url_for('Index.html'))
            else:
                flash('Invalid username or password.')
                return redirect(url_for('Index.html'))
        except Exception as e:
            print("Error executing query:", e)
            flash('Error executing query.')
            return redirect(url_for('Index.html'))

@app.route('/start_ride', methods=['POST'])
def start_ride():
    if 'username' in session: # Check if username is in session
        username = session['username']
        start_des = request.form['start_des']
        end_des = request.form['end_des']
        time = request.form['time']
        passenger_no = int(request.form['pass_no'])
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO rides (username, start_des, end_des, time, pass_no) VALUES (%s, %s, %s, %s, %s)", (username, start_des, end_des, time, passenger_no))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('Index.html'))
        except Exception as e:
            return "Error inserting data"
    else:
        flash('Please log in to start a ride.')
        return redirect(url_for('Index.html'))
@app.route('/get_ride', methods=['POST'])
def get_ride():
    if 'username' in session: # Check if username is in session
        username = session['username']
        start_des = request.form['start_des']
        end_des = request.form['end_des']
        time = request.form['time']
        cur = mysql.connection.cursor()
        try:
            # Corrected SQL query with parentheses around the values
            cur.execute("INSERT INTO rides (username, start_des, end_des, time) VALUES (%s, %s, %s, %s)", (username, start_des, end_des, time))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('Index.html')) # Assuming 'Index.html' is a route, otherwise use render_template
        except Exception as e:
            return "Error inserting data"
    else:
        flash('Please log in to get a ride.')
        return redirect(url_for('LoginSignup.html'))
    
if __name__ == '__main__':
    app.run(debug=True, port="7000")
