from Models.ComputerModel import ComputerModel
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 as sha256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://matse:matse222@134.130.90.167:5432/rechner_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)

class MainboardModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'mainboard'

    mainboard_id = db.Column(db.Integer, primary_key=True)
    producer = db.Column(db.String(100))
    name = db.Column(db.String(100))
    socket = db.Column(db.String(15))
    sockets = db.Column(db.Integer)
    chipset = db.Column(db.String(25))
    dimmslots = db.Column(db.Integer)
    pcieslots = db.Column(db.Integer)
    m2slots = db.Column(db.Integer)
    sataconnectors = db.Column(db.Integer)
    formfactor = db.Column(db.String(15))
    ddr = db.Column(db.String(10))

    def __init__(self, producer, name, socket, sockets, chipset, dimmslots, pcieslots, m2slots, sataconnectors, formfactor, ddr):
        self.producer = producer
        self.name = name
        self.socket = socket
        self.sockets = sockets
        self.chipset = chipset
        self.dimmslots = dimmslots
        self.pcieslots = pcieslots
        self.m2slots = m2slots
        self.sataconnectors = sataconnectors
        self.formfactor = formfactor
        self.ddr = ddr

    def __repr__(self):
        return f"<Mainboard {self.name}>"
