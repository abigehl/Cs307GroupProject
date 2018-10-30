#import secrets
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from files import app, db, bcrypt, mail
from files.form import (LoginForm, RegisterForm, RecipeForm, RequestResetForm, ResetPasswordForm,
                        UpdateProfileForm, PostForm, PostFormHungryFor, PostFormCurrentlyEating,
                        RecipeSearchForm, RecipeSearchForm)
from files.__init__ import users, rec, postss
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import re

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


def parser_first_round(key_words):
    remove_list = ['with', 'the']
    keywords = key_words
    keywords = re.sub(r'\b\w{1,2}\b', '', keywords)
    keywords = keywords.split()
    keywords = ' '.join([i for i in keywords if i not in remove_list])
    output = []
    for i in keywords.split():
        for z in range(0, len(i) - 1):
            element = i[0:z + 2]
            output.append(element)
    keywords = ' '.join(word for word in output)
    keywords = re.sub(r'\b\w{1,1}\b', '', keywords)
    keywords = keywords.split()
    keywords = [x + '*' for x in keywords]
    keywords = ' '.join(keywords)
    return keywords


def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ))


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

    if formCurrent.validate():
        post3 = postss(content_current=formCurrent.contentCurrent.data, link_current=formCurrent.linkCurrent.data, user_id=current_user.id, post_type="currentlyEating")
        db.session.add(post3)
        db.session.commit()
        flash('Your post has created', 'success')
        return redirect(url_for('homepage'))

    searchform = RecipeSearchForm()
    print('hello')
    print(searchform.keyWord.data)
    if searchform.validate_on_submit():
        print('hello')
        keywords = parser_first_round(searchform.keyWord.data)
        print(keywords)
        result = db.engine.execute("SELECT * FROM rec WHERE MATCH (rec_name, rec_description, rec_instruction, ing_1) AGAINST (%s IN BOOLEAN MODE)", keywords)
        for row in result:
            print(row)

        result = db.engine.execute("SELECT * FROM rec WHERE (minPrice BETWEEN 10 AND 20) OR (maxPrice BETWEEN 10 AND  20)")
        for row in result:
            print(row)

        result = db.engine.execute("SELECT * FROM rec WHERE calories BETWEEN 40 AND 150")
        for row in result:
            print(row)

    print(searchform.errors.items)
    return render_template('homepage.html', title='Home', form=form, form2=formNormalText, form3=formCurrent, searchform=searchform)


# @app.route('/search', methods=['GET', 'POST'])
# def search():

#     return render_template('homepage.html', form4=form4)


@app.route('/realhomepage')
def realhomepage():
    return render_template("homepageloggedin.html")


@app.route('/advancedsearch', methods=['GET', 'POST'])
def advancedsearch():
    return render_template("advancedsearchpage.html")


@app.route('/ourmission')
def ourmission():
    return render_template('OurMission.html')

################################################  USER SETTINGS  #####################################################


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    form4 = RecipeSearchForm()

    if form4.validate_on_submit():

        keywords = parser_first_round(form4.keyWord.data)
        print(keywords)
        result = db.engine.execute("SELECT * FROM rec WHERE MATCH (rec_name, rec_description, rec_instruction, ing_1) AGAINST (%s IN BOOLEAN MODE)", keywords)
        for row in result:
            print(row)

        result = db.engine.execute("SELECT * FROM rec WHERE (minPrice BETWEEN 10 AND 20) OR (maxPrice BETWEEN 10 AND  20)")
        for row in result:
            print(row)

        result = db.engine.execute("SELECT * FROM rec WHERE calories BETWEEN 40 AND 150")
        for row in result:
            print(row)

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
    return render_template('usersettings.html', form=form, form4=form4)

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

    recipes = rec.query.filter_by(user_id=current_user.id)
    image_file = url_for('static', filename='Images/' + current_user.profilePic)
    return render_template('ProfilePage.html', title='Profile', recipes=recipes, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent)


@app.route('/ProfilePage/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = postss.query.filter_by(id=post_id).first()

    current_db_sessions = db.session.object_session(post)
    current_db_sessions.delete(post)
    current_db_sessions.commit()

    return redirect(url_for('profile'))


@app.route("/repcipe/new", methods=['GET', 'POST'])
@login_required
def create_recipe():
    print("before")
    form = RecipeForm()
    print("after")
    
    if form.validate_on_submit():
        print("RECIPE NAME: " + form.rec_name.data)
        recipe = rec(rec_name=form.rec_name.data, prep_time=form.prep_time.data, cook_time=form.cook_time.data, rec_description=form.rec_description.data, rec_instruction=form.rec_instruction.data, ing_1=form.ing_1.data, ing_2=form.ing_2.data, ing_3=form.ing_3.data, ing_4=form.ing_4.data, ing_5=form.ing_5.data, ing_6=form.ing_6.data, ing_7=form.ing_7.data, ing_8=form.ing_8.data, ing_9=form.ing_9.data, ing_10=form.ing_10.data, calories=form.calories.data, fat=form.fat.data, cholesterol=form.cholesterol.data, sodium=form.sodium.data, user_id=current_user.id, minPrice=form.minPrice.data, maxPrice=form.maxPrice.data)
        print("add")
        db.session.add(recipe)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('profile'))
    return render_template('createrecipe.html', title='New Recipe', form=form)


@app.route("/recipe/<int:recipe_id>")
def showrecipe(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    return render_template('recipespage.html', title=rec.rec_name, rec=rec)


@app.route("/recipe/<int:recipe_id>/update", methods=['GET', 'POST'])
@login_required
def update_recipe(recipe_id):
    rec = rec.query.get_or_404(recipe_id)
    if rec.user_id != user.id:
        abort(403)
    form = RecipeForm()
    if form.validate_on_submit():
        #re.rec_url = form.rec_url.data
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
    if rec.user_id != current_user.id:
        abort(403)
    db.session.delete(rec)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('main.home'))


@app.route("/favorites/all")
@login_required
def favorites():
    favorites = favs.query.filter_by(user_id=current_user.id)
    return render_template('favoritesPage.html', title='Favorites Page', form=form, favorites=favorites)


@app.route("/favorites/<int:recipe_id>/add", methods=['POST', 'GET'])
@login_required
def add_fav(recipe_id):
    if request.methods == 'POST':
        favorite = favs(user_id=current_user.id, recipe_id=recipe_id)
        db.session.add(favs)
        db.session.commit()
        flash('Your favorite has been Added!', 'success')
    return redirect(url_for('add_fav', recipe_id=recipe_id))


@app.route("/favorites/<int:recipe_id>/delete", methods=['POST', 'GET'])
@login_required
def delete_fav(recipe_id):
    if request.methods == 'POST':
        favorite = favs.query.get_or_404(recipe_id)
        if favorite.user_id != current_user.id:
            abort(403)
            db.session.delete(favorite)
            db.session.commit()
            flash('Your post has been deleted!', 'success')
    return redirect(url_for('delete_fav', recipe_id=recipe_id))
