from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)




class ProcessorModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'processor'

    processor_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    producer = db.Column(db.String(100))
    clock = db.Column(db.String(10))
    architecture = db.Column(db.String(30))
    socket = db.Column(db.String(15))

    def __init__(self, name, producer, clock, architecture, socket):
        self.name = name
        self.producer = producer
        self.clock = clock
        self.architecture = architecture
        self.socket = socket

    def __repr__(self):
        return f"<Processor {self.name}>"