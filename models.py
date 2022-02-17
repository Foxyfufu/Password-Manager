from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager
from passwordEncryption import EncryptDecrypt
from werkzeug.security import generate_password_hash, check_password_hash
 
login = LoginManager()
db = SQLAlchemy()
encryptdecrypt = EncryptDecrypt()
 
class UserModel(UserMixin, db.Model):
    __tablename__ = 'user'
 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(), nullable=False)
    children = db.relationship('Manager', backref="e_mail", lazy=True)
 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
 
@login.user_loader
def load_user(id):
    return UserModel.query.get(int(id))

class Manager(db.Model):
    __tablename__ = 'entry'

    entry_id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(50), db.ForeignKey('user.email'), nullable=False)
    entry_website = db.Column(db.String, nullable=False)
    entry_username = db.Column(db.String(50), nullable=False)
    entry_email = db.Column(db.String(80), nullable=False)
    entry_encryptedPassword = db.Column(db.String(), nullable=False)

    def __repr__(self): #return a string containing a printable representation of an object ???
        return '<Manager %r>' % self.entry_id

    def encrypt_password(self, password):
        self.entry_encryptedPassword = encryptdecrypt.encrypt_password(password)

    def decrypt_password(self, encryptedPassword):
        decryptedpassword = encryptdecrypt.decrypt_password(encryptedPassword)
        decryptedPassword = decryptedpassword[2:-1]
        return decryptedPassword
