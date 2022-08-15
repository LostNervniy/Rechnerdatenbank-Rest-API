from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)

class ComputerCompleteModel(db.Model):
    __tablename__ = 'computers'
    __table_args__ = {'extend_existing': True, "schema": "rechner_db"}

    computer_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    edv = db.Column(db.String(6))
    # Objects
    room_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)

    ip = db.Column(db.Integer)
    # Objects
    os_id = db.Column(db.Integer)

    type = db.Column(db.String(50))
    # Objects
    motherboard_id = db.Column(db.Integer)

    note = db.Column(db.String(300))
    borrowable = db.Column(db.Boolean)
    storage = db.Column(db.String(250))

    def __init__(self, name, edv, room_id, user_id, ip, os_id, type, motherboard_id, note, borrowable, storage):
        self.name = name
        self.edv = edv
        self.room_id = room_id
        self.user_id = user_id
        self.ip = ip
        self.os_id = os_id
        self.type = type
        self.motherboard_id = motherboard_id
        self.note = note
        self.borrowable = borrowable
        self.storage = storage

    def __repr__(self):
        return f"<Computer {self.name}>"

