from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 as sha256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)


class UserModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True)
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    passwd = db.Column(db.String(256))
    role = db.Column(db.String(30))

    def __init__(self, email, firstname, lastname, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.role = role

    def __repr__(self):
        return f"<User {self.firstname + ' ' + self.lastname}>"

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)
