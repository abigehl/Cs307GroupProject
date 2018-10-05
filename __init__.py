from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
import os
from datetime import datetime
import time
#from django.db import IntegrityError


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = 'THIS_IS_SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'


app.secret_key = "helpmerecipe"
google_blueprint = make_google_blueprint(
    client_id="640840633381-8rrcgg5r9hru2al5e853jq95valimmd5.apps.googleusercontent.com",
    client_secret="YvDSgKVfGEM_nLblFbBPESZp",
    scope=[
        "https://www.googleapis.com/auth/plus.me",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
    offline=True,
)

facebook_blueprint = make_facebook_blueprint(
    client_id="1145745515594684",
    client_secret="350d8feaa14aa1a37212a8b3d4dd2694",
    scope=[
        "public_profile",
        "email"
    ],
)


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

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=30)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])

   # submit = SubmitField('Sign Up')


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





@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


app.register_blueprint(google_blueprint, url_prefix="/google_login")
app.register_blueprint(facebook_blueprint, url_prefix="/facebook_login")


@app.route('/login/forgot/newpass')
def newpass():
    form = RegisterForm()
    return render_template('forgotPassCode.html', form=form)


@app.route('/login/forgot')
def forgotp():
    form = RegisterForm()
    return render_template('forgotPass.html', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('homepageloggedin'))
    form = LoginForm()
    if form.validate_on_submit():
        user = users.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('homepageloggedin'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('main.html', title='Login', form=form)

#@app.route('/profil', methods=['GET','POST'])
#def profile_page():
 #   return render_template('ProfilePage.html')


@app.route('/createrecipe', methods=['GET','POST'])
def create_recipe():
    if(request.method == 'POST'):
        food_name = request.form["food"]
        prepTime = request.form["prep-time"]
        cookTime = request.form["cook-time"]
        recDescription = request.form["description"]
        recInstruction = request.form["instruction"]
        ingr1 = request.form["ing1"]
        ingr2 = request.form["ing2"]
        ingr3 = request.form["ing3"]
        ingr4 = request.form["ing4"]
        ingr5 = request.form["ing5"]
        ingr6 = request.form["ing6"]
        ingr7 = request.form["ing7"]
        ingr8 = request.form["ing8"]
        ingr9 = request.form["ing9"]
        ingr10 = request.form["ing10"]

        post = rec(rec_name=food_name, prep_time=prepTime,cook_time = cookTime, rec_description=recDescription, rec_instruction=recInstruction,ing_1=ingr1,ing_2=ingr2,ing_3=ingr3,ing_4=ingr4,ing_5=ingr5,ing_6=ingr6,ing_7=ingr7,ing_8=ingr8,ing_9=ingr9,ing_10=ingr10)

        db.session.add(post)
        db.session.commit()

    return render_template('createrecipe.html')


@app.route("/register", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('homepageloggedin'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = users(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('homepageloggedin'))
    return render_template('register.html', title='Register', form=form)


@app.route('/')
#@login_required
def homepage():
    if current_user.is_authenticated:
        return redirect(url_for('homepageloggedin'))

    return render_template('homepage.html')

@app.route('/realhomepage')
def realhomepage():
	return render_template("homepageloggedin.html")


@app.route('/facebook-google')
def fglogin():
    return render_template('facebook-google.html')

@app.route('/ourmission')
def ourmission():
	return render_template('OurMission.html')


@app.route('/settings' , methods=['GET', 'POST'])
def settings():
    if(request.method == 'POST'):
        current_user.firstName = request.form["firstname"]
        current_user.lastName = request.form["lastname"]
        current_user.displayName = request.form["displayname"]
        current_user.cookingExperience = request.form["cooking_experience"]
        current_user.profilePic=request.form["url"]
         
        db.session.commit()

    return render_template('usersettings.html')

@app.route('/usersettings') 
def updateUserSettings():
    
        return render_template('usersettings.html')

@app.route('/googleSignin', methods=['GET', 'POST'])
def googleSignin():
    # print(session)
    if not google.authorized:
        print("new user")
        return redirect(url_for("google.login"))
    try:
        # print(session)
        resp = google.get("/oauth2/v2/userinfo")
        assert resp.ok, resp.text

        post = users.query.filter_by(email=resp.json()["email"]).first()
        if not post:
            post = users(username=resp.json()["name"], password=resp.json()["id"], email=resp.json()["email"])  # (name="Annie", email="something@gmail")
            print(post)
            db.session.add(post)
            db.session.commit()
    except InvalidClientIdError:
        session.clear()
        return render_template('facebook-google.html')
    print("return to homepage")
    return render_template('homepageloggedin.html')

@app.route('/facebookSignin', methods=['GET', 'POST'])
def facebookSignin():
    #form = LoginForm()
    if not facebook.authorized:
        print("new user")
        return redirect(url_for("facebook.login"))
    try:
        # print(session)
        resp = facebook.get('/me?fields=id,name,email')
        post = users.query.filter_by(email=resp.json()["email"]).first()
        if not post:
            post = users(username=resp.json()["name"], password=resp.json()["id"], email=resp.json()["email"])  # (name="Annie", email="something@gmail")
            print(post)
            db.session.add(post)
            db.session.commit()
    except InvalidClientIdError:
        session.clear()
        print("error")
        return render_template('facebook-google.html')
    print("return to homepage")
    return render_template('homepageloggedin.html')


@app.route('/logout')
#@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))

@app.route('/homepageloggedin' , methods=['GET','POST'])
def homepageloggedin():
    if(request.method == 'POST'):
        postDescription = request.form["post_desc"]
        post = posts(status=postDescription)

        db.session.add(post)
        db.session.commit()
    return render_template('homepageloggedin.html')

@app.route('/ProfilePage')
def profile():
    return render_template('ProfilePage.html')

if __name__ == '__main__':
    app.run(debug=True)
