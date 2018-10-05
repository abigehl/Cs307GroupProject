from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
import os
from datetime import datetime


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app = Flask(__name__)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
app.config['SECRET_KEY'] = 'THIS_IS_SECRET'
db = SQLAlchemy(app)
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
    rec_name = db.Column('rec_name', db.String(100),primary_key=True)      
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

    submit = SubmitField('Sign up')


class users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode, unique=True)
    email = db.Column(db.Unicode, unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


app.register_blueprint(google_blueprint, url_prefix="/google_login")
app.register_blueprint(facebook_blueprint, url_prefix="/facebook_login")


@app.route('/login', methods=['GET', 'POST'])
def index():

    form = LoginForm()
    if form.validate_on_submit():
        user = users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)

                return redirect(url_for('homepage'))
        return '<h1>Invalid username or password</h1>'

    # if request.method == 'POST':
      #  username = request.form['username']
       # password = request.form['password']

       # post = users(name=username, email=password)

       # db.session.add(post)
        # db.session.commit()

    return render_template('main.html', form=form)

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


@app.route('/signup', methods=['GET', 'POST'])
def signup():

    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = users(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('homepage'))

        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    #################################################

    # if request.method == 'POST':
      #  username = request.form['username']
       # password = request.form['password']

       # post = users(name=username, email=password)

       # db.session.add(post)
        # db.session.commit()

    return render_template('register.html', title='Login', form=form)


@app.route('/', methods=['GET','POST'])
#@login_required
def homepage():
    if(request.method == 'POST'):
        postDescription = request.form["post_desc"]
        post = posts(status=postDescription)

        db.session.add(post)
        db.session.commit()

    return render_template('homepage.html')


@app.route('/facebook-google')
def fglogin():
    return render_template('facebook-google.html')


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
    return render_template('homepage.html')


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
    return render_template('homepage.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
