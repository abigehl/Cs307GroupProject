import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Index, func
from flask_bootstrap import Bootstrap
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import time
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from flask import Flask, render_template, request, redirect, url_for, session, flash


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = 'THIS_IS_SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'helpmerecipe@gmail.com'
app.config['MAIL_PASSWORD'] = 'FMNBUFa5Dp8ysmJ'


mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'


app.secret_key = "helpmerecipe"

from files import routes


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


class rec(db.Model):
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __searchable__ = ['rec_name', 'rec_description']
    id = db.Column(db.Integer, primary_key=True)
    rec_name = db.Column('rec_name', db.String(100), nullable=False)
    prep_time = db.Column('prep_time', db.String(50), default="")
    cook_time = db.Column('cook_time', db.String(50), default="")
    rec_description = db.Column('rec_description', db.Text, nullable=False)
    rec_instruction = db.Column('rec_instruction', db.Text, nullable=False)
    ings = db.Column('ings', db.String(1000), nullable=False)
    tags = db.Column('tags', db.String(500), nullable=False)
    minPrice = db.Column('minPrice', db.Integer)
    maxPrice = db.Column('maxprice', db.Integer)
    calories  = db.Column('calories', db.String(10),default ="")
    fat = db.Column('fat', db.String(10), default="")
    cholesterol = db.Column('cholesterol', db.String(10), default="")
    sodium = db.Column('sodium', db.String(10), default="")
    user_id = db.Column(db.Integer, nullable=False)
    recipePic = db.Column(db.String(80), default="spicy.jpg")
    dateposted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    rating = db.Column(db.Integer)
    number_of_ratings = db.Column(db.Integer)

    def __repr__(self, rating=rating, number_of_ratings=number_of_ratings):
       return "rec('{self.rating}',{self.number_of_ratings}'')"


class postss(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=True)
    link_current = db.Column(db.String(1000), nullable=True)
    content_current = db.Column(db.String(1000), nullable=True)
    post_type = db.Column(db.String(50), nullable=False)
    post_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return "postss('{self.user_id}')"


class post_comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, nullable=False)
    commentPost = db.Column(db.String(5000))
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return "post_comments('{self.post_id}')"


class users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profilePic = db.Column(db.String(40), default="emptyProf.png")
    firstName = db.Column(db.String(20), default="")
    lastName = db.Column(db.String(20), default="")
    displayName = db.Column(db.String(20), default="")
    cookingExperience = db.Column(db.String(12), default="Beginner")
    country = db.Column(db.String(30), default="")
    # posts= db.relationship('posts', backref='users', lazy=True)

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


class favs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    fav_rec_name = db.Column(db.String(100), nullable=False)
    fav_prep_time = db.Column(db.String(50), default="")
    fav_cook_time = db.Column(db.String(50), default="")
    fav_rec_description = db.Column(db.Text, nullable=False)
    fav_rec_instruction = db.Column(db.Text, nullable=False)
    fav_ing1 = db.Column(db.String(50), nullable=False)
    fav_ing2 = db.Column(db.String(50), default="")
    fav_minPrice = db.Column(db.Integer)
    fav_maxPrice = db.Column(db.Integer)
    fav_calories = db.Column(db.String(10), default = "")
    fav_fat = db.Column(db.String(10), default="")
    fav_cholestrol = db.Column(db.String(10), default="")
    fav_sodium = db.Column(db.String(10), default="")
    recipe_id = db.Column(db.Integer)
    fav_rec_creator = db.Column(db.String(50), nullable = False)


class followers(db.Model):
    followerid = db.Column(db.Integer, primary_key=True)
    followedid = db.Column(db.Integer, primary_key=True)
    followername = db.Column(db.String(80))
    followedname = db.Column(db.String(80))


class likers(db.Model):
    liked_post = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, primary_key=True)


class raters(db.Model):
    rated_recipe = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, primary_key=True)

#from models import users, rec, postss
# if __name__ == '__main__':
# manager.run()
# app.run(debug=True)
# db.drop_all()
# db.metadata.clear()
