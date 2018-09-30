import pymysql
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
db = SQLAlchemy(app)


class Example(db.Model):
    __tablename__ = 'users'
    name = db.Column('name', db.Unicode, primary_key=True)
    email = db.Column('email', db.Unicode)