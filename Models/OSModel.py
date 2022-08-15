from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)

class OSModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'operatingsystem'

    os_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    version = db.Column(db.String(20))

    def __init__(self, name, version):
        self.name = name
        self.version = version

    def __repr__(self):
        return f"<OS {self.name}>"
