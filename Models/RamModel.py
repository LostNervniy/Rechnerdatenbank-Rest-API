from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)


class RamModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'ram'

    ram_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    producer = db.Column(db.String(100))
    standard = db.Column(db.String(10))
    frequency = db.Column(db.Integer)
    capacity = db.Column(db.Integer)

    def __init__(self, name, producer, standard, frequency, capacity):
        self.name = name
        self.producer = producer
        self.standard = standard
        self.frequency = frequency
        self.capacity = capacity

    def __repr__(self):
        return f"<Ram {self.name}>"

