from __future__ import print_function
from flask import Flask, render_template, request, redirect, session, flash
from config import APP_KEY #encrypt cookies
from models import db, login, UserModel, Manager
from flask_login import login_required, current_user, login_user, logout_user
from flask_session import Session
from passwordGenerator import passwordGenerator
from Google import create_service
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# from functools import wraps
# from utils import generate_uid, divide_data

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = APP_KEY
Session(app)
passwordGeneration = passwordGenerator()

CLIENT_SECRET_FILE = 'credentials.json'
API_NAME = 'gmail'
API_VERSION = 'v1'
SCOPES = ['https://mail.google.com/']
service = create_service(CLIENT_SECRET_FILE, API_NAME, API_VERSION, SCOPES)

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
            # login_user(user)
            # return redirect('/home')
            return redirect('/security')

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
@app.route('/security', methods=['POST', 'GET'])
def security():
    if request.method == 'POST':
        OTPinput = request.form['OTP']
        if OTPinput == session['OTP']:
            user = session['user']
            login_user(user)
            return redirect('/home')

        else:
            return render_template('login.html')

    else:
        session['OTP'] = passwordGeneration.generateOTP()

        emailMsg = 'Your OTP is: ' + session['OTP']
        mimeMessage = MIMEMultipart()
        mimeMessage['to'] = 'lxj982005@gmail.com'
        mimeMessage['subject'] = 'SafePM OTP'
        mimeMessage.attach(MIMEText(emailMsg, 'plain'))
        raw_string = base64.urlsafe_b64encode(mimeMessage.as_bytes()).decode()

        message = service.users().messages().send(userId='me', body={'raw': raw_string}).execute()
        print(message)

        return render_template('security.html')

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
        
    # def reminder():	     
	#     return('Please change your password!')
    
    # schedule.every(5).seconds.do(reminder)

    return render_template('home.html', entries=entries)

@app.route('/delete/<int:entry_id>')
@login_required
def delete(entry_id):
    to_delete = Manager.query.get_or_404(entry_id) #get id, if no such id then error 404

    try:
        db.session.delete(to_delete)
        db.session.commit()
        return redirect('/home')

    except:
        return ('There was an error deleting this entry')
 
@app.route('/update/<int:entry_id>', methods=["GET", "POST"])
@login_required
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

@app.route('/generate')
@login_required
def generateRandom():
    temp = passwordGeneration.generatePassword()
    randomPassword = 'Your new password is: '+ temp
    e_mail = session['email']
    entries = Manager.query.filter_by(user_email=e_mail).all()
    for entry in entries:
        if entry.entry_encryptedPassword:
            entry.entry_encryptedPassword = entry.decrypt_password(entry.entry_encryptedPassword)
    return render_template('home.html', randompassword=randomPassword, entries = entries)

@app.route('/back')
@login_required
def back():
    return redirect('/home')

@app.route('/info')
def info():
    return render_template('info.html')

if __name__ == "__main__":
    app.run(debug=True)