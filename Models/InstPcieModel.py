from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://[USERNAME]:[PASSWORD]@[IP]:[PORT]/[SCHEMA]'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 75
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 100
db = SQLAlchemy(app)


class InstPcieModel(db.Model):
    __table_args__ = {"schema": "rechner_db"}
    __tablename__ = 'pcie_installed'

    pcie_id = db.Column(db.Integer)
    computer_id = db.Column(db.Integer)
    p_installed_id = db.Column(db.Integer, primary_key=True)

    def __init__(self, pcie_id, computer_id):
        self.pcie_id = pcie_id
        self.computer_id = computer_id

    def __repr__(self):
        return f"<Installed Ram {self.pcie_id}>"

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
        db.session.remove()