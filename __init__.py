from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
import os
from datetime import datetime
import time
from form import *
from models import *
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_uploads import UploadSet, configure_uploads, IMAGES
#from django.db import IntegrityError


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = 'THIS_IS_SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'
photos = UploadSet('photos', IMAGES)
app.config['UPLOADED_PHOTOS_DEST'] = 'static/Images'
configure_uploads(app, photos)

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

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    print("save profile pic")
    return picture_fn


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
        return redirect(url_for('homepage'))
    form = LoginForm()
    if form.validate_on_submit():
        user = users.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('homepage'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('main.html', title='Login', form=form)

#@app.route('/profil', methods=['GET','POST'])
#def profile_page():
 #   return render_template('ProfilePage.html')

@app.route("/register", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = users(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/')
#@login_required
def homepage():
    return render_template('homepage.html')


@app.route('/ourmission')
def ourmission():
	return render_template('OurMission.html')

@app.route('/favorites')
def favorites():
	return render_template('favoritesPage.html')

@app.route('/settings' , methods=['GET', 'POST'])
@login_required
def settings():
    # form = UpdateAccountForm()
    # print("something")
    # if form.validate_on_submit():
    #     print("submit")
    #     print(form.profilePic.data)
    #     if form.profilePic.data:
    #         picture_file = save_picture(form.profilePic.data)
    #         print("get profile pic")
    #         current_user.profilePic = picture_file
    #     print("first Name")
    #     current_user.firstName = request.form["firstname"]
    #     current_user.lastName = request.form["lastname"]
    #     current_user.displayName = request.form["displayname"]
    #     current_user.cookingExperience = request.form["cooking_experience"]
    #     db.session.commit()
    #     flash('Your account has been updated!', 'success')
    #     return redirect(url_for('ProfilePage'))
    # else:
    #     print(form)
    #     print(form.errors)
    # image_file = url_for('static', filename='profile_pics/' + current_user.profilePic)
    # return render_template('usersettings.html', title='usersettings', form=form)
    if(request.method == 'POST'):
        # current_user.firstName = request.form["firstname"]
        # current_user.lastName = request.form["lastname"]
        # current_user.displayName = request.form["displayname"]
        # current_user.cookingExperience = request.form["cooking_experience"]
        #current_user.profilePic=request.form["url"]
        print("post")
        if len(request.files) != 0:
            #filename = photos.save(request.files['photo'])
            file = request.files['photo']
            print(file)
        #db.session.commit()

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
        return redirect(url_for('login'))
    print("return to homepage")
    return redirect(url_for('homepage'))

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
        return redirect(url_for('login'))
    print("return to homepage")
    return redirect(url_for('homepage'))


@app.route('/logout')
#@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))


@app.route('/ProfilePage')
def profile():
    return render_template('ProfilePage.html')


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



if __name__ == '__main__':
    app.run(debug=True)
