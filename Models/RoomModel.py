from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)


class RoomModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'room'

    room_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(75))
    etage = db.Column(db.String(10))
    description = db.Column(db.String(350))


    def __init__(self, name, etage, description):
        self.name = name
        self.etage = etage
        self.description = description

    def __repr__(self):
        return f"<Room {self.name}>"
