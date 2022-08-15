from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)

class InstRamModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'ram_installed'

    ram_id = db.Column(db.Integer)
    computer_id = db.Column(db.Integer)
    r_installed_id = db.Column(db.Integer, primary_key=True)

    def __init__(self, ram_id, computer_id):
        self.ram_id = ram_id
        self.computer_id = computer_id

    def __repr__(self):
        return f"<Installed Ram {self.ram_id}>"

