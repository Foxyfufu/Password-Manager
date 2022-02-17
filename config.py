TESTING = True
DEBUG = True
FLASK_ENV = 'development'
APP_KEY = 'GDtfDCFYjD' #change this
SESSION_TYPE = 'filesystem'
SESSION_PERMANENT = False
SQLALCHEMY_DATABASE_URI = 'sqlite:///passwordmanager.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

MAIL_SERVER ='smtp.mailtrap.io'
MAIL_USERNAME  = '97e041d5e367c7'
MAIL_PASSWORD  = 'cfaf5b99f8bafb'
MAIL_DEFAULT_SENDER = 'lxj982005@gmail.com'