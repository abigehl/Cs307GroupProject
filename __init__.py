from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
#import secrets
import os
from datetime import datetime
import time
from form import *
from models import *
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from posts.route import posts
#from django.db import IntegrityError


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

app.register_blueprint(posts)

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

@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


app.register_blueprint(google_blueprint, url_prefix="/google_login")
app.register_blueprint(facebook_blueprint, url_prefix="/facebook_login")


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password reset Request',
                  sender='helpmerecipe@gmail.com',
                  recipients=[user.email])
    #msg.body = f'To reset your password, visit the following link' {url_for('reset_token', token = token, _external = True)} 'If you did not make this request then simply ignore this email and no changes will be made.'
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    form = RequestResetForm()
    # if form was submited and validated
    if form.validate_on_submit():
        user = users.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password. ', 'info')
        return redirect(url_for('login'))

    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))

    user = users.verify_reset_token(token)
    #token is invalid or expired
    print(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    # token is valid -> let change password
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print("USER ID", user.id)
        print("USER PASSWORD", form.password.data)
        #user.password = hashed_password
        update_this = users.query.filter_by(id=user.id).first()
        # print(update_this.username)
        #update_this.firstName = 'WILLIAM'
        # print(update_this.firstName)
        db.engine.execute("UPDATE users SET password = %s WHERE ID = %s", (hashed_password, user.id))
        db.session.commit()
        flash('Your password has been updated', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


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
# def profile_page():
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


@app.route('/', methods=['GET', 'POST'])
#@login_required
def homepage():
    if(request.method == 'POST'):
        written_post = request.form["post_desc"]

        post = posts(description=written_post)

        db.session.add(post)
        db.session.commit()

    return render_template('homepage.html')


@app.route('/realhomepage')
def realhomepage():
    return render_template("homepageloggedin.html")


@app.route('/ourmission')
def ourmission():
    return render_template('OurMission.html')

################################################  USER SETTINGS  #####################################################


def is_filled(data):
    if data == None:
        return False
    if data == '':
        return False
    if data == []:
        return False
    return True


def save_picture(form_picture):
    # randomize picture name so there is no colition with other picture
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/Images', picture_fn)
    form_picture.save(picture_path)
    return picture_fn


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            print(picture_file)
            db.engine.execute("UPDATE users SET profilePic = %s WHERE id = %s", (picture_file, current_user.id))
        if(is_filled(form.username.data)):
            db.engine.execute("UPDATE users SET username = %s WHERE id = %s", (form.username.data, current_user.id))
        if(is_filled(form.firstname.data)):
            db.engine.execute("UPDATE users SET firstname = %s WHERE id = %s", (form.firstname.data, current_user.id))
        if(is_filled(form.lastname.data)):
            db.engine.execute("UPDATE users SET lastname = %s WHERE id = %s", (form.lastname.data, current_user.id))
        if(is_filled(form.email.data)):
            db.engine.execute("UPDATE users SET firstname = %s WHERE id = %s", (form.firstname.data, current_user.id))
        if(is_filled(form.cooking_exp.data)):
            db.engine.execute("UPDATE users SET cookingExperience = %s WHERE id = %s", (form.cooking_exp.data, current_user.id))
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.firstname.data = current_user.firstName
        form.lastname.data = current_user.lastName
        form.email.data = current_user.email
        form.cooking_exp.data = current_user.cookingExperience
    # if(request.method == 'POST'):
    #     current_user.firstName = request.form["firstname"]
    #     current_user.lastName = request.form["lastname"]
    #     current_user.displayName = request.form["displayname"]
    #     if request.form["cooking_experience"] != None:
    #         print("hello")
    #         current_user.cookingExperience = request.form["cooking_experience"]
    #     current_user.profilePic = request.form["url"]

    #     db.engine.execute("UPDATE users SET firstName = %s, lastName = %s, displayName =  %s, cookingExperience = %s, profilePic = %s WHERE id = %s",
    #                       (current_user.firstName, current_user.lastName, current_user.displayName,
    #                        current_user.cookingExperience, current_user.profilePic, current_user.id))
    #     db.session.commit()
    return render_template('usersettings.html', form=form)



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
    # return render_template('ProfilePage.html')
    image_file = url_for('static', filename='Images/' + current_user.profilePic)
    return render_template('ProfilePage.html', title='Profile', image_file=image_file)


@app.route('/createrecipe', methods=['GET', 'POST'])
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

        post = rec(rec_name=food_name, prep_time=prepTime, cook_time=cookTime, rec_description=recDescription, rec_instruction=recInstruction, ing_1=ingr1, ing_2=ingr2, ing_3=ingr3, ing_4=ingr4, ing_5=ingr5, ing_6=ingr6, ing_7=ingr7, ing_8=ingr8, ing_9=ingr9, ing_10=ingr10)

        db.session.add(post)
        db.session.commit()

    return render_template('createrecipe.html')

@app.route("/repcipe/new", methods=['GET', 'POST'])
@login_required
def new_post():
    print("before")
    form = RecipeForm()
    print("after")
    if form.validate_on_submit():
        print("recipe")
        recipe = rec(rec_name=form.rec_name.data, author=current_user, prep_time=form.prep_time.data,  cook_time=form.cook_time.data, rec_description=form.rec_description.data, rec_instruction=form.rec_instruction.data, ing_1=form.ing_1.data, ing_2=form.ing_2.data, ing_3=form.ing_3.data, ing_4=form.ing_4.data, ing_5=form.ing_5.data, ing_6=form.ing_6.data, ing_7=form.ing_7.data, ing_8=form.ing_8.data, ing_9=form.ing_9.data, ing_10=form.ing_10.data, calories=form.calories.data, fat=form.fat.data, cholesterol=form.cholesterol.data, sodium=form.sodium.data, user_id = user.id, minPrice=form.minPrice.data, maxPrice=form.maxPrice.data)
        print("add")
        db.session.add(recipe)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('main'))
    return render_template('createrecipe.html', title='New Recipe',form=form)

@app.route("/recipe/<int:recipe_id>")
def showrecipe(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    return render_template('xxx.html', title=rec.rec_name, post=post)

@app.route("/recipe/<int:recipe_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    if rec.user_id != user.id:
        abort(403)
    form = RecipeForm()
    if form.validate_on_submit():
        re.rec_name=form.rec_name.data
        re.author=current_user
        re.prep_time=form.prep_time.data
        re.cook_time=form.cook_time.data
        re.rec_description=form.rec_description.data
        re.rec_instruction=form.rec_instruction.data
        re.ing_1=form.ing_1.data
        re.ing_2=form.ing_2.data
        re.ing_3=form.ing_3.data
        re.ing_4=form.ing_4.data
        re.ing_5=form.ing_5.data
        re.ing_6=form.ing_6.data
        re.ing_7=form.ing_7.data
        re.ing_8=form.ing_8.data
        re.ing_9=form.ing_9.data
        re.ing_10=form.ing_10.data
        re.calories=form.calories.data
        re.fat=form.fat.data
        re.cholesterol=form.cholesterol.data
        re.sodium=form.sodium.data
        re.minPrice=form.minPrice.data
        re.maxPrice=form.maxPrice.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('xxxx', post_id=post.id))

    return render_template('xxxx.html', title='Update Recipe', form=form)



@app.route("/recipe/<int:recipe_id>/delete", methods=['POST'])
@login_required
def delete_post(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    if rec.user_id != user.id:
        abort(403)
    db.session.delete(rec)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('main.home'))

if __name__ == '__main__':
    app.run(debug=True)
