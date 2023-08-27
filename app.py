from flask import Flask, render_template, request, redirect, session, jsonify, url_for
import bcrypt
import sqlite3
import threading
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db_connection():
    if 'db_connection' not in threading.current_thread().__dict__:
        threading.current_thread().db_connection = sqlite3.connect('messages.db')
    return threading.current_thread().db_connection

def init_db():
    connection = get_db_connection()
    cursor = connection.cursor()
    
    # Create the users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            profile_pic TEXT,
            is_new INTEGER
        )
    ''')
    
    # Create the messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            content TEXT
        )
    ''')
    
    connection.commit()


def get_profile_pic(username):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT profile_pic FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    if result and result[0]:
        return url_for('static', filename='profile_pics/' + result[0])
    else:
        return url_for('static', filename='default_profile_pic.jpg')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/')
def home():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT id, username, content FROM messages ORDER BY id DESC')
    messages = cursor.fetchall()
    
    user_is_new = False
    profile_pic = None  # Initialize the profile_pic variable
    
    if 'username' in session:
        cursor.execute('SELECT profile_pic FROM users WHERE username = ?', (session['username'],))
        result = cursor.fetchone()
        profile_pic = result[0] if result else None
    
    if 'username' not in session:
        user_is_new = True
    
    return render_template('index.html', messages=messages, user_is_new=user_is_new, profile_pic=profile_pic)


@app.route('/post_message', methods=['POST'])
def post_message():
    username = session.get('username')
    message = request.form.get('message')

    if username and message:
        # Check if the message is the delete command
        if message.lower() == '/delete all messages':
            delete_all_messages()  # Call function to delete all messages
        else:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO messages (username, content) VALUES (?, ?)', (username, message))
            connection.commit()

    return redirect('/')


@app.route('/update_profile_pic', methods=['POST'])
def update_profile_pic():
    if 'username' in session and 'file' in request.files:
        username = session['username']
        file = request.files.get('file')  # Use request.files.get() to retrieve the uploaded file
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # Update the profile picture filename in the database
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('UPDATE users SET profile_pic = ? WHERE username = ?', (filename, username))
            connection.commit()

    return redirect('/')

# Route to the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
                session['username'] = username
                return redirect('/')

    return render_template('login.html')

@app.route('/delete_all_messages', methods=['POST'])
def delete_all_messages():
    try:
        if 'username' in session and session['username'] == 'admin':
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('DELETE FROM messages')  # Delete all messages
            connection.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Permission denied'})
    except Exception as e:
        print('Error deleting messages:', e)
        return jsonify({'success': False})


# Route to the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Store the username and hashed password in the users table
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            connection.commit()
            session['username'] = username
            return redirect('/')
    return render_template('signup.html')

@app.route('/logout', methods=['POST'])
def logout():
    if 'username' in session:
        session.pop('username', None)
    return redirect('/')

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    # Fetch the username of the message
    cursor.execute('SELECT username FROM messages WHERE id = ?', (message_id,))
    result = cursor.fetchone()
    
    if result:
        username = result[0]
        
        # Check if the user is the author of the message
        if 'username' in session and session['username'] == username:
            cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
            connection.commit()
            
            # Check if user has more messages, if not, remove from users table
            cursor.execute('SELECT id FROM messages WHERE username = ?', (username,))
            user_messages = cursor.fetchall()
            
            if not user_messages:
                cursor.execute('DELETE FROM users WHERE username = ?', (username,))
                connection.commit()
    
    return redirect('/')



@app.route('/get_messages')
def get_messages():
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute('''
        SELECT m.id, m.username, m.content, u.profile_pic
        FROM messages m
        LEFT JOIN users u ON m.username = u.username
        ORDER BY m.id DESC
    ''')
    messages = cursor.fetchall()
    return jsonify(messages)



if __name__ == '__main__':
    init_db()  # Initialize the database tables
    app.jinja_env.globals.update(get_profile_pic=get_profile_pic)
    app.run(debug=True)