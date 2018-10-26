import secrets
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from files import app, db, bcrypt, mail
from files.form import (LoginForm, RegisterForm, RecipeForm, RequestResetForm, ResetPasswordForm,
                        UpdateProfileForm, PostForm, PostFormHungryFor, PostFormCurrentlyEating,
                        RecipeSearchForm)
from files.__init__ import users, rec, postss
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

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

app.register_blueprint(google_blueprint, url_prefix="/google_login")
app.register_blueprint(facebook_blueprint, url_prefix="/facebook_login")


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password reset Request',
                  sender='helpmerecipe@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
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
        update_this = users.query.filter_by(id=user.id).first()
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
    form = PostFormHungryFor()

    if form.validate_on_submit():
        toSend = "I am hungry for " + form.content.data
        post = postss(content=toSend, user_id=current_user.id, post_type="hungryFor")
        db.session.add(post)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('homepage'))

    formNormalText = PostForm()

    if formNormalText.validate_on_submit():
        post2 = postss(content=formNormalText.contentNormal.data, user_id=current_user.id, post_type="boringPost")
        db.session.add(post2)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('homepage'))

    formCurrent = PostFormCurrentlyEating()

    if formCurrent.validate_on_submit():
        post3 = postss(content_current=formCurrent.contentCurrent.data, link_current=formCurrent.linkCurrent.data, user_id=current_user.id, post_type="currentlyEating")
        db.session.add(post3)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('homepage'))
    #############################################SEARCHING FILTERS IN HOMEPAGE##########################################
    #RecipeSearchForm = RecipeSearchForm()

    # if RecipeSearchForm.validate_on_submit():

    return render_template('homepage.html', title='Home', form=form, form2=formNormalText, form3=formCurrent)


@app.route('/realhomepage')
def realhomepage():
    return render_template("homepageloggedin.html")


@app.route('/advancedsearch')
def advancedsearch():
    return render_template("advancedsearchpage.html")


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
    return render_template('usersettings.html', form=form)

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


@app.route('/ProfilePage', methods=['GET', 'POST'])
@login_required
def profile():
    form = PostFormHungryFor()

    if form.validate_on_submit():
        toSend = "I am hungry for " + form.content.data
        post = postss(content=toSend, user_id=current_user.id, post_type="hungryFor")
        db.session.add(post)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('profile'))

    formNormalText = PostForm()

    if formNormalText.validate_on_submit():
        post2 = postss(content=formNormalText.contentNormal.data, user_id=current_user.id, post_type="boringPost")
        db.session.add(post2)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('profile'))

    formCurrent = PostFormCurrentlyEating()

    if formCurrent.validate_on_submit():
        post3 = postss(content_current=formCurrent.contentCurrent.data, link_current=formCurrent.linkCurrent.data, user_id=current_user.id, post_type="currentlyEating")
        db.session.add(post3)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('profile'))

    allposts = postss.query.all()
    image_file = url_for('static', filename='Images/' + current_user.profilePic)
    return render_template('ProfilePage.html', title='Profile', image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent)


@app.route("/repcipe/new", methods=['GET', 'POST'])
@login_required
def create_recipe():
    print("before")
    form = RecipeForm()
    print("after")
    if form.validate_on_submit():
        print("recipe")
        recipe = rec(rec_url=form.rec_url.data, rec_name=form.rec_name.data, author=current_user, prep_time=form.prep_time.data, cook_time=form.cook_time.data, rec_description=form.rec_description.data, rec_instruction=form.rec_instruction.data, ing_1=form.ing_1.data, ing_2=form.ing_2.data, ing_3=form.ing_3.data, ing_4=form.ing_4.data, ing_5=form.ing_5.data, ing_6=form.ing_6.data, ing_7=form.ing_7.data, ing_8=form.ing_8.data, ing_9=form.ing_9.data, ing_10=form.ing_10.data, calories=form.calories.data, fat=form.fat.data, cholesterol=form.cholesterol.data, sodium=form.sodium.data, user_id=user.id, minPrice=form.minPrice.data, maxPrice=form.maxPrice.data)
        print("add")
        db.session.add(recipe)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('main'))
    return render_template('createrecipe.html', title='New Recipe', form=form)


@app.route("/recipe/<int:recipe_id>")
def showrecipe(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    return render_template('xxx.html', title=rec.rec_name, rec=rec)


@app.route("/recipe/<int:recipe_id>/update", methods=['GET', 'POST'])
@login_required
def update_recipe(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    if rec.user_id != user.id:
        abort(403)
    form = RecipeForm()
    if form.validate_on_submit():
        re.rec_url = form.rec_url.data
        re.rec_name = form.rec_name.data
        re.author = current_user
        re.prep_time = form.prep_time.data
        re.cook_time = form.cook_time.data
        re.rec_description = form.rec_description.data
        re.rec_instruction = form.rec_instruction.data
        re.ing_1 = form.ing_1.data
        re.ing_2 = form.ing_2.data
        re.ing_3 = form.ing_3.data
        re.ing_4 = form.ing_4.data
        re.ing_5 = form.ing_5.data
        re.ing_6 = form.ing_6.data
        re.ing_7 = form.ing_7.data
        re.ing_8 = form.ing_8.data
        re.ing_9 = form.ing_9.data
        re.ing_10 = form.ing_10.data
        re.calories = form.calories.data
        re.fat = form.fat.data
        re.cholesterol = form.cholesterol.data
        re.sodium = form.sodium.data
        re.minPrice = form.minPrice.data
        re.maxPrice = form.maxPrice.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('showrecipe', recipe_id=rec.id))

    return render_template('createrecipe.html', title='Update Recipe', form=form)


@app.route("/recipe/<int:recipe_id>/delete", methods=['POST'])
@login_required
def delete_recipe(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    if rec.user_id != user.id:
        abort(403)
    db.session.delete(rec)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('main.home'))


@app.route("/favorites")
def favorites():
    return render_template('favoritesPage.html', title='Favorites Page', form=form)
