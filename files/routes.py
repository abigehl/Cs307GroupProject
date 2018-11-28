import secrets
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from files import app, db, bcrypt, mail
from files.form import (LoginForm, RegisterForm, RecipeForm, RequestResetForm, ResetPasswordForm,
                        UpdateProfileForm, PostForm, PostFormHungryFor, PostFormCurrentlyEating,
                        RecipeSearchForm,  RecipeSearchForm, CommentForm, FindFriends)
from files.__init__ import users, rec, postss, favs, post_comments, followers, likers
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import re
from sqlalchemy import func

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

def parser_search_sufix(key_words):
    remove_list = ['with', 'the']
    keywords = key_words
    keywords = re.sub(r'\b\w{1,2}\b', '', keywords)
    keywords = keywords.split()
    keywords = ' '.join([i for i in keywords if i not in remove_list])
    output = []
    for i in keywords.split():
        element = i[len(i)-3:len(i)]
        output.append(element)
    keywords = ' '.join(word for word in output)
    keywords = re.sub(r'\b\w{1,1}\b', '', keywords)
    keywords = keywords.split()
    keywords = ["%" + x + "%" for x in keywords]
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

################################################################## HOME ##########################################
@app.route('/', methods=['GET', 'POST'])
#@login_required
def homepage():

    formsearch = RecipeSearchForm()

    #favRecipes = favs.query.filter_by(user_id=current_user.id)
    form = PostFormHungryFor()
    if current_user.is_authenticated:
        # allrecipes = db.engine.execute("SELECT rec_name, rec_description, user_id, recipePic, dateposted, username, followername, rating from  (rec  left join (select id, username from users) as a on rec.user_id = a.id) left join followers on (followers.followedid = rec.user_id and followerid = %s)", current_user.id)
        # allposts = db.engine.execute("SELECT content_current, content, user_id, link_current, post_date, username, followername, followerid from \
        #                                 postss left join (select id, username from users) as a on postss.user_id = a.id \
        #                                     left join followers on (followers.followedid = postss.user_id and followerid = %s)", current_user.id )
        allrecipes = db.engine.execute("SELECT rec.id as id, rec_name, rec_description, user_id, recipePic, dateposted, username, followername, rating, number_of_ratings  from  (rec  left join (select id, username from users) as a on rec.user_id = a.id) \
                                            left join followers on (followers.followedid = rec.user_id and followerid = %s) \
                                        UNION \
                                        select b.id, content_current, content, user_id, link_current, post_date, username, followername, userid, nlikes from \
                                        (select * from postss left join likers on postss.id = likers.liked_post and likers.userid = %s) as b left join (select id, username from users) as a on b.user_id = a.id \
                                            left join followers on (followers.followedid = b.user_id and followerid = %s) \
                                        ORDER BY dateposted desc;", current_user.id, current_user.id, current_user.id)

    else:
        allrecipes = db.engine.execute("SELECT * FROM rec WHERE 1 = 0")


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

    return render_template('homepage.html', title='Home', form5=formsearch, form=form, form2=formNormalText, form3=formCurrent, allrecipes = allrecipes)

################################################################## RECIPE SEARCH ###################################################
@app.route('/search', methods=['GET', 'POST'])
def search():

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()


    if request.method == 'POST':

        minmax = request.form['minmax']
        minmax = minmax.replace('-', '')
        minmax = minmax.replace('$', '').split()

        calories = request.form['calories']
        calories = calories.replace('-', '')
        calories = calories.replace('$', '').split()

    if formsearch.validate_on_submit():   
        if is_filled(formsearch.keyWord.data):
            keywords = parser_first_round(formsearch.keyWord.data)
            keywords_sufix = parser_search_sufix(formsearch.keyWord.data)

            recipes = db.engine.execute("SELECT * FROM (SELECT * FROM rec WHERE (minPrice <= %s AND maxprice >= %s) AND ( calories >= %s AND calories <= %s ) AND \
                ((MATCH (rec_name, rec_description, rec_instruction, ing_1, ing_2, ing_3, ing_4, ing_5, ing_6, ing_7, ing_8, ing_9, ing_10) \
                    AGAINST (%s IN BOOLEAN MODE))OR (rec_name LIKE %s ))) as b left join (select id as useridd, username from users) as a on b.user_id = a.useridd",minmax[1], minmax[0], calories[0], calories[1], keywords, keywords_sufix)
            return render_template('homepage.html', form5=formsearch, form=form, form2=formNormalText, form3=formCurrent, recipes = recipes)


        else:

            recipes = db.engine.execute("SELECT * FROM rec WHERE (minPrice <= %s AND maxprice >= %s) AND ( calories >= %s AND calories <= %s )", minmax[1], minmax[0], calories[0], calories[1])
            return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent, recipes = recipes)



    return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent)

@app.route('/searchthing/<string:thing>', methods=['GET', 'POST'])
def searchthings(thing):

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    if thing is "":
        return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent)

    else:
        
        recipes=db.engine.execute("SELECT * FROM rec WHERE((MATCH (rec_name, rec_description, rec_instruction, ing_1, ing_2, ing_3, ing_4, ing_5, ing_6, ing_7, ing_8, ing_9, ing_10) AGAINST (%s IN BOOLEAN MODE)))", thing)
        return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent, recipes=recipes)

@app.route('/searchadvanced/<string:things>', methods=['GET', 'POST'])
def searchadvanced(things):
    print("things")
    print(things)
    
    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    if things is "":
        
        return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent)

    else:
        words = things.split(';')
        words= list(filter(None, words))
        print(words)
        recipes=db.engine.execute("SELECT * FROM rec WHERE((MATCH (rec_name, rec_description, rec_instruction, ing_1, ing_2, ing_3, ing_4, ing_5, ing_6, ing_7, ing_8, ing_9, ing_10) AGAINST (%s IN BOOLEAN MODE)))", words)
        return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent, recipes=recipes)
    
    return render_template('homepage.html', form5=formsearch,  form=form, form2=formNormalText, form3=formCurrent)


@app.route('/advancedsearch', methods=['GET', 'POST'])
def advancedsearch():
    formsearch = RecipeSearchForm()
    print(formsearch.keyWord.data)
    if formsearch.validate_on_submit():
        print(formsearch.keyWord.data)
    return render_template("advancedsearchpage.html", form5=formsearch)


@app.route('/ourmission')
def ourmission():
    return render_template('OurMission.html')

################################################  USER SETTINGS  #####################################################


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    formsearch = RecipeSearchForm()

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
    return render_template('usersettings.html', form=form, form5=formsearch)

    return render_template('usersettings.html', form5=formsearch)


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

############################################################# PROFILE PAGE #############################################################################
@app.route('/ProfilePage', methods=['GET', 'POST'])
@login_required
def profile():

    followers = db.engine.execute("SELECT followername FROM followers where followedid = %s", current_user.id)
    following = db.engine.execute("SELECT followedname FROM followers where followerid = %s", current_user.id)
    formsearch = RecipeSearchForm()

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
    favRecipes = favs.query.filter_by(user_id=current_user.id)

    image_file = url_for('static', filename='Images/' + current_user.profilePic)
    count2 = 0

    for x in recipes:
        count2 = count2 + 1

    count = 0

    for x in favRecipes:
        count = count + 1

    if count == 0 and count2 != 0:
        return render_template('ProfilePage.html', title='Profile', form5=formsearch, followers = followers, following = following, recipes=recipes, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent)
    elif count == 0 and count2 == 0:
        return render_template('ProfilePage.html', title='Profile', form5=formsearch, followers = followers, following = following, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent)
    elif count != 0 and count2 == 0:
        return render_template('ProfilePage.html', title='Profile', form5=formsearch, followers = followers, following = following, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent, favRecipes=favRecipes)
    else:
        return render_template('ProfilePage.html', title='Profile', form5=formsearch, followers = followers, following = following, recipes=recipes, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent, favRecipes=favRecipes)

########################################################################## POST DELETE PROFILE PAGE #############################################################
@app.route('/ProfilePage/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = postss.query.filter_by(id=post_id).first()

    current_db_sessions = db.session.object_session(post)
    current_db_sessions.delete(post)
    current_db_sessions.commit()

    return redirect(url_for('profile'))
######################################################################### POST UPDATE PROFILE PAGE ##############################################################

@app.route('/ProfilePage/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = postss.query.get(post_id)

    #print("post content: " + post.content)
    #string = post.content.split(" ", 4)[4]
    #print(string)

    formsearch = RecipeSearchForm()

    form = PostFormHungryFor()
    if form.validate_on_submit():
        hungryFood = "I am hungry for " + form.content.data
        db.engine.execute("UPDATE postss SET content = %s WHERE ID = %s", (hungryFood, post_id))
        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('editPost.html', form=form, form5=formsearch, post=post)

######################################################################## CREATE NEW RECIPE ########################################################################
@app.route("/recipe/new", methods=['GET', 'POST'])
@login_required
def create_recipe():
    formsearch = RecipeSearchForm()

    form = RecipeForm()

    if form.validate_on_submit():
        if form.recipePic.data:
            recipe_file = save_picture(form.recipePic.data)
            recipe = rec(rec_name=form.rec_name.data, prep_time=form.prep_time.data, cook_time=form.cook_time.data, rec_description=form.rec_description.data, rec_instruction=form.rec_instruction.data, ing_1=form.ing_1.data, ing_2=form.ing_2.data, ing_3=form.ing_3.data, ing_4=form.ing_4.data, ing_5=form.ing_5.data, ing_6=form.ing_6.data, ing_7=form.ing_7.data, ing_8=form.ing_8.data, ing_9=form.ing_9.data, ing_10=form.ing_10.data, calories=form.calories.data, fat=form.fat.data, cholesterol=form.cholesterol.data, sodium=form.sodium.data, user_id=current_user.id, minPrice=form.minPrice.data, maxPrice=form.maxPrice.data, recipePic=recipe_file)
        else:
            print("RECIPE NAME: " + form.rec_name.data)
            recipe = rec(rec_name=form.rec_name.data, prep_time=form.prep_time.data, cook_time=form.cook_time.data, rec_description=form.rec_description.data, rec_instruction=form.rec_instruction.data, ing_1=form.ing_1.data, ing_2=form.ing_2.data, ing_3=form.ing_3.data, ing_4=form.ing_4.data, ing_5=form.ing_5.data, ing_6=form.ing_6.data, ing_7=form.ing_7.data, ing_8=form.ing_8.data, ing_9=form.ing_9.data, ing_10=form.ing_10.data, calories=form.calories.data, fat=form.fat.data, cholesterol=form.cholesterol.data, sodium=form.sodium.data, user_id=current_user.id, minPrice=form.minPrice.data, maxPrice=form.maxPrice.data)
        print("add")
        db.session.add(recipe)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('profile'))
    return render_template('createrecipe.html', title='New Recipe', form=form, form5=formsearch)

###################################################################### FULL RECIPE DISPLAY ######################################################################
@app.route("/recipe/<int:recipe_id>", methods=['POST'])
def showrecipe(recipe_id):
    formsearch = RecipeSearchForm()
    recc = rec.query.get_or_404(recipe_id)
    return render_template('recipespage.html', title=recc.rec_name, rec=recc, form5=formsearch)

###################################################################### RECIPE UPDATE ###########################################################################3
@app.route("/recipe/<int:recipe_id>/update", methods=['GET', 'POST'])
@login_required
def update_recipe(recipe_id):
    recipee = rec.query.get(recipe_id)
    formsearch = RecipeSearchForm()

    form = RecipeForm()

    if form.validate_on_submit():
        if form.recipePic.data:
            recipe_file = save_picture(form.recipePic.data)
            print(recipe_file)
            db.engine.execute("UPDATE rec SET recipePic = %s WHERE id = %s", (recipe_file, recipe_id))
        reRec_name = form.rec_name.data
        rePrep_time = form.prep_time.data
        reCook_time = form.cook_time.data
        if len(form.rec_description.data)==0:
                reRec_description= recipee.rec_description
        else:
            reRec_description = form.rec_description.data
        if len(form.rec_instruction.data)==0:
            reRec_instruction= recipee.rec_instruction
        else:
            reRec_instruction = form.rec_instruction.data
        reIng_1 = form.ing_1.data
        reIng_2 = form.ing_2.data
        reIng_3 = form.ing_3.data
        reIng_4 = form.ing_4.data
        reIng_5 = form.ing_5.data
        reIng_6 = form.ing_6.data
        reIng_7 = form.ing_7.data
        reIng_8 = form.ing_8.data
        reIng_9 = form.ing_9.data
        reIng_10 = form.ing_10.data
        reCalories = form.calories.data
        reFat = form.fat.data
        reCholesterol = form.cholesterol.data
        reSodium = form.sodium.data
        reMinPrice = form.minPrice.data
        reMaxPrice = form.maxPrice.data
        print("add recipe")
        db.engine.execute("UPDATE rec SET rec_name = %s, prep_time = %s, cook_time = %s, rec_description = %s, rec_instruction = %s, ing_1 = %s, ing_2 = %s,ing_3 = %s,ing_4 = %s,ing_5 = %s,ing_6 = %s,ing_7 = %s, ing_8 = %s,ing_9 = %s,ing_10 = %s, minPrice = %s, maxPrice = %s,calories = %s,fat = %s, cholesterol = %s, sodium = %s WHERE ID = %s", (reRec_name, rePrep_time, reCook_time, reRec_description,reRec_instruction, reIng_1, reIng_2, reIng_3, reIng_4, reIng_5, reIng_6, reIng_7, reIng_8, reIng_9, reIng_10,reMinPrice,reMaxPrice, reCalories, reFat, reCholesterol, reSodium, recipe_id))
        db.session.commit()
        return redirect(url_for('profile'))

    return render_template('editRecipe.html',form = form, form5 = formsearch, rec=recipee)

############################################################################ RECIPE DELETE ####################################################################
@app.route("/recipe/<int:recipe_id>/delete", methods=['POST'])
@login_required
def delete_recipe(recipe_id):
    recipee = rec.query.filter_by(id=recipe_id).first()

    current_db_sessions = db.session.object_session(recipee)
    current_db_sessions.delete(recipee)
    current_db_sessions.commit()

    favrecipee = favs.query.filter_by(id=recipe_id).first()

    current_db_sessions = db.session.object_session(favrecipee)
    current_db_sessions.delete(favrecipee)
    current_db_sessions.commit()

    return redirect(url_for('profile'))

#############################################################################
@app.route("/favorites/all", methods=['GET'])
@login_required
def favorites():
    formsearch = RecipeSearchForm()
    favorites = favs.query.filter_by(user_id=current_user.id)

    return render_template('favoritesPage.html', title='Favorites Page', favorites=favorites, form5=formsearch)

##############################################################################3
@app.route("/favorites/<int:recipe_id>/add", methods=['POST', 'GET'])
@login_required
def add_fav(recipe_id):
    recipee = rec.query.filter_by(id=recipe_id).first()

    reRec_name = recipee.rec_name
    rePrep_time = recipee.prep_time
    reCook_time = recipee.cook_time
    reRec_description = recipee.rec_description
    reRec_instruction = recipee.rec_instruction
    reIng_1 = recipee.ing_1
    reIng_2 = recipee.ing_2
    reIng_3 = recipee.ing_3
    reIng_4 = recipee.ing_4
    reIng_5 = recipee.ing_5
    reIng_6 = recipee.ing_6
    reIng_7 = recipee.ing_7
    reIng_8 = recipee.ing_8
    reIng_9 = recipee.ing_9
    reIng_10 = recipee.ing_10
    reCalories = recipee.calories
    reFat = recipee.fat
    reCholesterol = recipee.cholesterol
    reSodium = recipee.sodium
    reMinPrice = recipee.minPrice
    reMaxPrice = recipee.maxPrice

    favorite = favs(user_id=current_user.id, fav_rec_name=reRec_name, fav_prep_time = rePrep_time, fav_cook_time=reCook_time, fav_rec_description=reRec_description, fav_rec_instruction=reRec_instruction,fav_ing1 = reIng_1,fav_ing2 = reIng_2,fav_ing3 = reIng_3,fav_ing4 = reIng_4,fav_ing5 = reIng_5,fav_ing6 = reIng_6,fav_ing7 = reIng_7,fav_ing8 = reIng_8,fav_ing9 = reIng_9,fav_ing10 = reIng_10,fav_minPrice = reMinPrice, fav_maxPrice = reMaxPrice, fav_calories=reCalories, fav_fat = reFat, fav_cholestrol = reCholesterol,fav_sodium=reSodium)
    db.session.add(favorite)
    db.session.commit()

    # form = PostFormHungryFor()
    # formNormalText = PostForm()
    # formCurrent = PostFormCurrentlyEating()
    # formsearch = RecipeSearchForm()

    return redirect(url_for('profile'))


@app.route("/favorites/<int:fav_id>/delete", methods=['POST', 'GET'])
@login_required
def delete_fav(fav_id):
    post = favs.query.filter_by(id=fav_id).first()
    print (fav_id)
    current_db_sessions = db.session.object_session(post)
    current_db_sessions.delete(post)
    current_db_sessions.commit()

    return redirect(url_for('favorites'))






#--------------------------------------------------------------------------------------------------------------------------------------------
# COMMENT SECTION
#--------------------------------------------------------------------------------------------------------------------------------------------

@app.route("/post/<int:post_id>/comment", methods=['POST', 'GET'])
@login_required
def comment_post(post_id):

    commentForm = CommentForm()
    if commentForm.validate_on_submit():
        comm = post_comments(post_id = post_id, commentPost=commentForm.commentBox.data, user_id = current_user.id)
        db.session.add(comm)
        db.session.commit()

        return redirect(url_for('all_comments'))

    return render_template('testComment.html', commentForm=commentForm)

@app.route("/allComments", methods=['POST', 'GET'])
@login_required
def all_comments():

    allComments = post_comments.query.filter_by(post_id=65)
    return render_template('testComment2.html', allComments = allComments)
#--------------------------------------------------------------------------------------------------------------------------------------------
#COMMENT SECTION
#--------------------------------------------------------------------------------------------------------------------------------------------

@app.route("/discovery", methods=['POST', 'GET'])
@login_required
def discovery():

    #recipes = rec.query.all();
    #posts = postss.query.all();
    obj = rec.query.count()
    recipes = rec.query.order_by(func.rand()).first()
    recuser = users.query.get(recipes.user_id)
    print(recipes.dateposted)
    formsearch = RecipeSearchForm()
    return render_template('discovery.html', rec = recipes, recuser = recuser, form5=formsearch)

@app.route("/map", methods=['POST', 'GET'])
def map():
    formsearch = RecipeSearchForm()
    return render_template('map.html',  form5=formsearch)

@app.route("/findfriends", methods=['POST', 'GET'])
@login_required
def findfriends():

    formsearch = RecipeSearchForm()
    findfriends = FindFriends()
    allrecipes = db.engine.execute("SELECT rec.id as id, rec_name, rec_description, user_id, recipePic, dateposted, username, followername, rating, number_of_ratings  from  (rec  left join (select id, username from users) as a on rec.user_id = a.id) \
                                            left join followers on (followers.followedid = rec.user_id and followerid = %s) \
                                        UNION \
                                        select b.id, content_current, content, user_id, link_current, post_date, username, followername, userid, nlikes from \
                                        (select * from postss left join likers on postss.id = likers.liked_post and likers.userid = %s) as b left join (select id, username from users) as a on b.user_id = a.id \
                                            left join followers on (followers.followedid = b.user_id and followerid = %s) \
                                        ORDER BY dateposted desc;", current_user.id, current_user.id, current_user.id)
    if findfriends.validate_on_submit:

        friends = db.engine.execute("SELECT * from (users left join followers on followers.followedid = users.id and followerid = %s) where username = %s", current_user.id, findfriends.friend.data)
    return render_template('findfriends.html',  form5=formsearch, findfriends = findfriends, friends = friends, allrecipes = allrecipes)

############################################################################# FOLLOW OTHER USERS #######################################

@app.route("/follow/<int:followedid><string:followedname>/add", methods=['POST', 'GET'])
@login_required
def add_follower(followedid, followedname):


    follower = followers(followerid = current_user.id, followedid = followedid, followername = current_user.username, followedname = followedname)
    db.session.add(follower)
    db.session.commit()

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    return redirect(url_for('homepage'))

############################################################################# UNFOLLOW OTHER USERS ################################3##
@app.route("/follow/<int:followedid><int:followerid>/remove", methods=['POST', 'GET'])
@login_required
def remove_follower(followedid, followerid):


    db.engine.execute("DELETE FROM followers WHERE followedid = %s AND followerid = %s", followedid, followerid)

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    return redirect(url_for('homepage'))

########################################################################## REMOVE LIKE ######################################
@app.route("/like/<int:postid>/remove", methods=['POST', 'GET'])
@login_required
def remove_like(postid):
    

    db.engine.execute("DELETE FROM likers WHERE liked_post = %s AND userid = %s", postid, current_user.id)
    db.engine.execute("UPDATE postss SET nlikes = nlikes - 1 where id = %s", postid)

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    return redirect(url_for('homepage'))

########################################################################### ADD LIKE ########################################
@app.route("/like/<int:postid>/add", methods=['POST', 'GET'])
@login_required
def add_like(postid):
    
    print("Hello : ", postid)

    like = likers(liked_post = postid, userid = current_user.id)

    # luike = postss.query.filter_by(id=postid).first()
    db.engine.execute("UPDATE postss SET nlikes = nlikes + 1 where id = %s", postid)
    db.session.add(like)
    db.session.commit()

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    return redirect(url_for('homepage'))


########################################################################### OTHER PROFILE PAGE VIEW ##################################
@app.route('/otherprofilepage/<int:hisid>', methods=['GET', 'POST'])
@login_required
def showprofile(hisid):


    #users = db.engine.execute("SELECT * FROM users WHERE id = %s", hisid)
    userss = users.query.filter_by(id = hisid).first()


    image_file = url_for('static', filename='Images/' + userss.profilePic)

    formsearch = RecipeSearchForm()
    form = PostFormHungryFor()
    formNormalText = PostForm()
    formCurrent = PostFormCurrentlyEating()

    allposts = postss.query.all()
    recipes = rec.query.filter_by(user_id=hisid)
    favRecipes = favs.query.filter_by(user_id=hisid)
    followers = db.engine.execute("SELECT followername FROM followers where followedid = %s", hisid)
    following = db.engine.execute("SELECT followedname FROM followers where followerid = %s", hisid)

    count2 = 0

    for x in recipes:
        count2 = count2 + 1

    count = 0

    for x in favRecipes:
        count = count + 1

    if count == 0 and count2 != 0:
        return render_template('ProfilePageOthers.html', title='Profile', form5=formsearch, followers = followers, following = following, users = userss, image_file=image_file, recipes=recipes, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent)
    elif count == 0 and count2 == 0:
        return render_template('ProfilePageOthers.html', title='Profile', form5=formsearch, followers = followers, following = following, users = userss, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent)
    elif count != 0 and count2 == 0:
        return render_template('ProfilePageOthers.html', title='Profile', form5=formsearch, followers = followers, following = following, users = userss, image_file=image_file, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent, favRecipes=favRecipes)
    else:
        return render_template('ProfilePageOthers.html', title='Profile', form5=formsearch, followers = followers, following = following, users = userss, image_file=image_file,recipes=recipes, allPosts=allposts, form=form, form2=formNormalText, form3=formCurrent, favRecipes=favRecipes)
