import json, sqlite3, click, functools, os, hashlib,time, random, sys, hashlib
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request




### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;

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

INSERT INTO users VALUES(null,"admin", "password",123);
INSERT INTO users VALUES(null,"bernardo", "omgMPC",321);
INSERT INTO notes VALUES(null,2,"1993-09-23 10:10:10","hello my friend",1234567890);
INSERT INTO notes VALUES(null,2,"1993-09-23 12:10:10","i want lunch pls",1234567891);

""")

### ADDED FUNCTIONS ###
def generate_password_hash(password, salt):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed_password

### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)
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
            
            
        elif request.form['submit_button'] == 'upload file':
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
            
            
            
    
    db = connect_db()
    c = db.cursor()
    statement = """SELECT * FROM notes WHERE assocUser = ?""" 
    c.execute(statement, (session['userid'],))
    notes = c.fetchall()
    print(notes)
    
    return render_template('notes.html',notes=notes,importerror=importerror)


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
        
        

    