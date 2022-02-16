from flask import Flask, render_template, request, redirect, session, flash, url_for
from config import APP_KEY #encrypt cookies
from models import db, login, UserModel, Manager
from flask_login import login_required, current_user, login_user, logout_user
from flask_session import Session
import os

# from functools import wraps
# from utils import generate_uid, divide_data

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = APP_KEY
Session(app)

db.init_app(app)
@app.before_first_request
def create_table():
    #db.drop_all()
    db.create_all()

login.init_app(app)
login.login_view = 'login'

#log in the user
@app.route('/', methods = ['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')
     
    if request.method == 'POST':
        email = request.form['email']
        user = UserModel.query.filter_by(email = email).first()

        if user is not None and user.check_password(request.form['password']):
            session['user'] = user
            session['email'] = email
            login_user(user)
            return redirect('/home')
            #return redirect('/security')

        else:
            flash("Your e-mail or password is incorrect")   
    return render_template('login.html')

#register a new user
@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect('/home')
     
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        if UserModel.query.filter_by(email = email).first():
            flash("There is already an account registered under this e-mail address.")
            return redirect('/register')

        if not username or not password:
            flash("You must provide both a username and a password.")
            return redirect('/register')
        
        if username == password:
            flash("Username and password cannot be the same.")
            return redirect('/register')

        user = UserModel(email=email, username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    return render_template('register.html')

#second factor authorisation
# @app.route("/login/2fa/")
# def login_2fa():
#     # generating random secret key for authentication
#     secret = pyotp.random_base32()
#     return render_template("login_2fa.html", secret=secret)

# @app.route('/home')
# @login_required
# def home():
#     return render_template('home.html')

#log out the user
@app.route('/logout')
def logout():
    logout_user()
    session.pop('user',None)
    return redirect('/')

@app.route('/home', methods=['POST', 'GET'])
@login_required
def index():
    if request.method == 'POST':
        entry_website = request.form['newWebsite']
        entry_email = request.form['newEmail']
        entry_username = request.form['newUsername']
        entry_password = request.form['newPassword']
        new_entry = Manager(user_email=session['email'], entry_website=entry_website, 
        entry_email=entry_email, entry_username=entry_username )
        new_entry.encrypt_password(entry_password)

        try:
            db.session.add(new_entry)
            db.session.commit()
            return redirect('/home')
        
        except:
            return ('There was an error adding this entry')

    else:
        e_mail = session['email']
        entries = Manager.query.filter_by(user_email=e_mail).all()
        for entry in entries:
            if entry.entry_encryptedPassword:
                entry.entry_encryptedPassword = entry.decrypt_password(entry.entry_encryptedPassword)

        return render_template('home.html', entries=entries)

@app.route('/delete/<int:entry_id>')
def delete(entry_id):
    to_delete = Manager.query.get_or_404(entry_id) #get id, if no such id then error 404

    try:
        db.session.delete(to_delete)
        db.session.commit()
        return redirect('/home')

    except:
        return ('There was an error deleting this entry')
 
@app.route('/update/<int:entry_id>', methods=["GET", "POST"])
def update(entry_id):
    entry = Manager.query.get_or_404(entry_id)

    if request.method == 'POST':
        print(request.form)
        entry.entry_website = request.form['updateWebsite']
        entry.entry_email = request.form['updateEmail']
        entry.entry_username = request.form['updateUsername']
        entry.encrypt_password(request.form['updatePassword'])

        try:
            db.session.commit()
            return redirect('/home')

        except Exception as e:
            return (str(e))

    else:
        return render_template('update.html', entry=entry)

if __name__ == "__main__":
    app.run(debug=True)