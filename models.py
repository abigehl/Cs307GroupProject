from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from __init__ import db, login_manager, app


class rec(db.Model):

    rec_name = db.Column('rec_name', db.String(100), primary_key=True)
    prep_time = db.Column('prep_time', db.String(50))
    cook_time = db.Column('cook_time', db.String(50))
    rec_description = db.Column('rec_description', db.Text)
    rec_instruction = db.Column('rec_instruction', db.Text)
    ing_1 = db.Column('ing_1', db.String(50))
    ing_2 = db.Column('ing_2', db.String(50))

    ing_3 = db.Column('ing_3', db.String(50))
    ing_4 = db.Column('ing_4', db.String(50))
    ing_5 = db.Column('ing_5', db.String(50))
    ing_6 = db.Column('ing_6', db.String(50))
    ing_7 = db.Column('ing_7', db.String(50))
    ing_8 = db.Column('ing_8', db.String(50))
    ing_9 = db.Column('ing_9', db.String(50))
    ing_10 = db.Column('ing_10', db.String(50))

    Calories = db.Column('Calories', db.String(50))
    Fat = db.Column('Fat', db.String(50))
    Cholesterol = db.Column('Cholesterol', db.String(50))
    Sodium = db.Column('Sodium', db.String(50))

    def __repr__(self):
        return 'rec({self.rec_name}, {self.prep_time}, {self.cook_time}, {self.rec_instruction}, {self.rec_description}, {self.Fat}, {self.Cholesterol}, {self.Sodium}, {self.Calories})'


class posts(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(5000), primary_key=True)
    #title = db.Column(db.String(100), nullable=False)
    #content = db.Column(db.Text, nullable=False)
    #user_id = db.Column(db.Integer, nullable=False)

    #def __repr__(self):
     #   return "posts('{self.status}', '{self.title}', '{self.content}', '{self.user_id}')"


class users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode, unique=True, nullable=False)
    email = db.Column(db.Unicode, unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profilePic = db.Column(db.String(40), default="../static/Images/emptyProf.png")
    firstName = db.Column(db.String(20), default="")
    lastName = db.Column(db.String(20), default="")
    displayName = db.Column(db.String(20), default="")
    cookingExperience = db.Column(db.String(12), default="Beginner")
    country = db.Column(db.String(30), default="")
    #posts= db.relationship('posts', backref='users', lazy=True)
    # CREATING TOKEN FOR PASSWORD RESET

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    # METHOD FOR TOKEN VERIFICATION

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return users.query.get(user_id)

    def __repr__(self):
        return "users('{self.username}', {self.email}', {self.password}', {self.profilePic}', {self.firstName}', {self.lastName}', {self.displayName}',{self.cookingExperience}',{self.country}')"
