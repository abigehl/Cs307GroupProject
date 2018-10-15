from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from .. import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))

class rec(db.Model):

    rec_name = db.Column('rec_name', db.String(100), primary_key=True)
    prep_time = db.Column('prep_time', db.String(50))
    cook_time = db.Column('cook_time', db.String(50))
    rec_description = db.Column('rec_description',db.String(1000))
    rec_instruction = db.Column('rec_instruction',db.String(10000))
    ing_1 = db.Column('ing_1',db.String(50))
    ing_2 = db.Column('ing_2',db.String(50))

    ing_3 = db.Column('ing_3',db.String(50))
    ing_4 = db.Column('ing_4',db.String(50))
    ing_5 = db.Column('ing_5',db.String(50))
    ing_6 = db.Column('ing_6',db.String(50))
    ing_7 = db.Column('ing_7',db.String(50))
    ing_8 = db.Column('ing_8',db.String(50))
    ing_9 = db.Column('ing_9',db.String(50))
    ing_10 = db.Column('ing_10',db.String(50))

    Calories = db.Column('Calories',db.String(50))
    Fat = db.Column('Fat',db.String(50))
    Cholesterol = db.Column('Cholesterol',db.String(50))
    Sodium = db.Column('Sodium',db.String(50))


class posts(db.Model):
    status = db.Column('status', db.String(5000),primary_key=True)


class users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode)
    email = db.Column(db.Unicode)
    password = db.Column(db.String(80))
    profilePic= db.Column(db.String(40), default="../static/Images/emptyProf.png", nullable=False)
    firstName= db.Column(db.String(20), default="", nullable=False)
    lastName= db.Column(db.String(20), default="", nullable=False)
    displayName= db.Column(db.String(20), default="", nullable=False)
    cookingExperience= db.Column(db.String(12), default="Beginner", nullable=False)
    country= db.Column(db.String(30), default="", nullable=False)
