import json, sqlite3, click, functools, os, hashlib,time, random, sys, hashlib
import io
import platform
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request, send_file


### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

admin_salt = 128391
admin_password = "aoisjdioasjd091283"
admin_hashed_password = hashlib.pbkdf2_hmac('sha256', admin_password.encode('utf-8'), admin_salt, 100000)

developer_salt = 293579
developer_password = "aid09asjd0asd09asud0"
developer_hashed_password = hashlib.pbkdf2_hmac('sha256', developer_password.encode('utf-8'), developer_salt, 100000)

beta_salt = 2935790
beta_password = "8q98dqyw8dy0qwd"
beta_hashed_password = hashlib.pbkdf2_hmac('sha256', beta_password.encode('utf-8'), beta_salt, 100000)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS notes;
    DROP TABLE IF EXISTS files;

    CREATE TABLE notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assocUser INTEGER NOT NULL,
        dateWritten DATETIME NOT NULL,
        note TEXT NOT NULL,
        publicID INTEGER NOT NULL
    );

    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL, 
        salt STRING NOT NULL
    );

    CREATE TABLE files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assocUser TEXT NOT NULL,
        filename TEXT NOT NULL, 
        data BLOB NOT NULL
    );
    """)
    
    # Insert the users with their hashed passwords and salts
    db.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", 
               ("admin", admin_hashed_password.hex(), admin_salt))
    db.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", 
               ("developer", developer_hashed_password.hex(), developer_salt))
    db.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", 
               ("beta", beta_hashed_password.hex(), beta_salt))

    # Insert some sample notes
    db.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (?, ?, ?, ?)", 
               (2, "1993-09-23 10:10:10", "A place to keep all my notes, how great.", 1234567890))
    db.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (?, ?, ?, ?)", 
               (2, "1993-09-23 12:10:10", "A great place to keep my thoughts!", 1234567891))
    db.execute("INSERT INTO notes (assocUser, dateWritten, note, publicID) VALUES (?, ?, ?, ?)", 
               (2, "1993-09-23 10:10:10", "So I don't forget: 8q98dqyw8dy0qwd", 1234567890))

### ADDED FUNCTIONS ###
def generate_password_hash(password, salt):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password

### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)

# File upload ...
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4 MB

init_db() # Remember to remove, OBSOBSOBS


### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))


@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    #Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()
            
            statement = """INSERT INTO notes(id, assocUser, dateWritten, note, publicID) 
                           VALUES (NULL, ?, ?, ?, ?)"""
            
            c.execute(statement, (session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, random.randrange(1000000000, 9999999999)))
            #c.execute(statement)

            
            db.commit()
            db.close()
            
            
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()
            statement = """SELECT * from NOTES where publicID = ?"""
            c.execute(statement, (noteid,))
            result = c.fetchall()
            if(len(result)>0):
                row = result[0]
                
                statement = """INSERT INTO notes(id, assocUser, dateWritten, note, publicID) 
                               VALUES (NULL, ?, ?, ?, ?)"""
                c.execute(statement, (session['userid'], row[2], row[3], row[4]))
            else:
                importerror="No such note with that ID!"
            db.commit()
            db.close()

        elif request.form['submit_button'] == 'alt upload file':
            f = request.files['file'] 
            f.save(f.filename)   
            print("The name of the file I have uploaded:", f.filename)
            f.seek(0) # Apparently we have to reset pointer -_-
            note = f.read().decode('utf-8') 
            db = connect_db()
            c = db.cursor()

            statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,%s,'%s','%s',%s);""" %(session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, random.randrange(1000000000, 9999999999))
            
            print(statement)
            c.executescript(statement)

            
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'Check if user exists':

            searchname = request.form['searchname']
            db = connect_db()
            c = db.cursor()
            statement = """SELECT COUNT(*) FROM users WHERE username = '%s'""" %(searchname,)
            c.executescript(statement)
            userExists = c.fetchall()
            print(userExists)
            statement = f"""INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,{session['userid']},'{time.strftime('%Y-%m-%d %H:%M:%S')}','{userExists}',{random.randrange(1000000000, 9999999999)});"""  
            c.executescript(statement)

            db.commit()
            db.close()
            

        elif request.form['submit_button'] == 'old add note':
            note = note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()

            statement = f"""INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,{session['userid']},'{time.strftime('%Y-%m-%d %H:%M:%S')}','{note}',{random.randrange(1000000000, 9999999999)});"""  
            
            print(statement)
            c.executescript(statement)

            tmp = c.fetchone()
            statement = f"""INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,{session['userid']},'{time.strftime('%Y-%m-%d %H:%M:%S')}','{tmp}',{random.randrange(1000000000, 9999999999)});"""  
            c.executescript(statement)

            db.commit()
            db.close()
            
        elif request.form['submit_button'] == 'upload file':
            uploaded_file = request.files['fileinput']
          
            
            if uploaded_file and uploaded_file.filename:
                file_data = uploaded_file.read()  # read file as binary data
                filename = uploaded_file.filename
                
                # upload to database (as Blob) maybe we should store it in a directory on the server instead...
                db = connect_db()
                c = db.cursor()
                statement = """INSERT INTO files (assocUser, filename, data)
                                VALUES (?, ?, ?)"""
                c.execute(statement, (session['userid'], filename, file_data))
                db.commit()
                db.close()
            else:
                importerror="Something went wrong. Select a file with a file name"
            
    
    db = connect_db()
    c = db.cursor()
    statement = """SELECT * FROM notes WHERE assocUser = ?""" 
    c.execute(statement, (session['userid'],))
    notes = c.fetchall()
    print(notes)

    os_name = os.name
    platform_system = platform.system()
    platform_release = platform.release()
    
    return render_template('notes.html',notes=notes,importerror=importerror, 
                           os_name=os_name,
                           platform_system=platform_system,
                           platform_release=platform_release)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        
        # First retrieve the matching salt for the user
        salt_statement = """SELECT salt FROM users WHERE username = ?"""
        c.execute(salt_statement, (username,))
        salt = c.fetchone()
        # It's in a tuple for some reason, get it out of there...
        actual_salt = salt[0]
        print("THIS IS THE SALT USED ON LOGIN")
        print(actual_salt)
             
        
        
        # print("THIS IS THE ACTUAL HASH")
        # print(actual_salt)
        # Using the salt, hash the password and see if it matches the stored hashed password
        hashed_password = generate_password_hash(password, actual_salt)
        print("THIS IS THE HASHED ENTERED PASSWORD ON LOGIN")
        print(hashed_password)
        
        
        statement = """SELECT * FROM users WHERE username = ? AND password = ?"""        
        c.execute(statement, (username, hashed_password))
        print(hashed_password)
        result = c.fetchall()

        if len(result) > 0:
            session.clear()
            session['logged_in'] = True
            session['userid'] = result[0][0]
            session['username']=result[0][1]
            return redirect(url_for('index'))
        else:
            error = "Wrong username or password!"
    return render_template('login.html',error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        

        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        
        # pass_statement = """SELECT * FROM users WHERE password = ?""" 
        
        #c.execute(pass_statement, (password,))
        #if(len(c.fetchall())>0):
        #    errored = True
        #    passworderror = "An error occurred during registration. Please try again."

        user_statement = """SELECT * FROM users WHERE username = ?"""
        c.execute(user_statement, (username,))
        if(len(c.fetchall())>0):
            errored = True
            usererror = "That username is already in use by someone else!"
        else:
            salt = os.urandom(32)
            hashed_password = generate_password_hash(password, salt)
            statement = """INSERT INTO users(id, username, password, salt) 
                           VALUES(null, ?, ?, ?)""" 
            print(statement)
            
            print("THIS IS THE SALT USED ON REGISTRATION")
            print(salt)
             
            c.execute(statement, (username,hashed_password,salt))
            print("THIS IS THE HASHED PASSWORD ON REGISTRATION")
            print(hashed_password)
            db.commit()
            db.close()
            return f"""<html>
                        <head>
                            <meta http-equiv="refresh" content="2;url=/" />
                        </head>
                        <body>
                            <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                        </body>
                        </html>
                        """
        
        db.commit()
        db.close()
    return render_template('register.html',usererror=usererror,passworderror=passworderror)


@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))


@app.route("/files/<username>", methods=['GET', 'POST'])
@login_required
def get_user_files(username):
    
    if session['username'] != username:
        return "Unauthorized", 403  # If the username doesn't match, return an error

    
    db = connect_db()
    c = db.cursor()
    
    # file upload if post request
    if request.method == 'POST':
        # Get the uploaded file from the request
        file = request.files['file']

        # make sure there is an uploaded file with an allowed name (Could be spoofed, whatever)
        ALLOWED_EXTENSIONS = {'txt'} 
        
        file_allowed = False
        if len(file.filename) > 0:
            file_allowed = '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        
        if file_allowed:
            # check if user already has 10 files
            statement = """SELECT COUNT(*) FROM files WHERE assocUser = ?"""
            c.execute(statement, (username,))
            file_count = c.fetchone()[0]

            if file_count >= 10:
                return 'Too many files', 400
            
            # Read the file content as a binary blob
            file_data = file.read()
            # Insert the file into the database
            file_upload_statement = "INSERT INTO files (assocUser, filename, data) VALUES (?, ?, ?)"
            c.execute(file_upload_statement, (username, file.filename, file_data))
            db.commit()
            db.close()
            
            db = connect_db()
            c = db.cursor()
            # get user files again after upload
            statement = """SELECT * FROM files WHERE assocUser = ?""" 
            c.execute(statement, (username,))

            user_files = c.fetchall()
            print("USER FILES: ")
            print(user_files)
        
            return render_template('files.html', username=username, user_files=user_files)
        else:
            return 'Invalid file', 400
            

    statement = """SELECT * FROM files WHERE assocUser = ?""" 
    c.execute(statement, (username,))
    user_files = c.fetchall()
    
    print("USER FILES: ")
    print(user_files)

    return render_template('files.html', username=username, user_files=user_files)


@app.route("/files/", methods=['GET'])
def get_all_files():
    db = connect_db()
    c = db.cursor()
    
    statement = """SELECT * FROM files"""
    c.execute(statement)
    all_files = c.fetchall()

    # Close the database connection
    db.close()

    return render_template('all_files.html', all_files=all_files)






@app.route("/download/<file_id>")
@login_required
def download_file(file_id):
    
    db = connect_db()
    c = db.cursor()

    # get files binary data from the database using the file_id
    c.execute("SELECT filename, data FROM files WHERE id = ?", (file_id,))
    file = c.fetchone()

    if file:
        filename, file_data = file
        db.close()

        # io.BytesIO converts the file data into a file object
        return send_file(io.BytesIO(file_data),mimetype='application/octet-stream',as_attachment=True, download_name=filename)
                        
    else:
        db.close()
        return "File not found", 404


if __name__ == "__main__":
    #create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if(len(sys.argv)==2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport) # runs on machine ip address to make it visible on network
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")
        
        