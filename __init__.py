from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
import os


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app = Flask(__name__)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
db = SQLAlchemy(app)

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
        "public profile",
        "email"
    ],
)


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class users(db.Model):
    username = db.Column(db.Unicode, primary_key=True)
    email = db.Column(db.Unicode)


app.register_blueprint(google_blueprint, url_prefix="/google_login")
app.register_blueprint(facebook_blueprint, url_prefix="/facebook_login")

@app.route('/', methods=['GET', 'POST'])
def index():

    #################################################
    form = LoginForm()
    if form.validate_on_submit():
        return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    #################################################

    # if request.method == 'POST':
      #  username = request.form['username']
       # password = request.form['password']

       # post = users(name=username, email=password)

       # db.session.add(post)
        # db.session.commit()

    return render_template('main.html', form=form)


@app.route('/facebook-google')
def fglogin():
    return render_template('facebook-google.html')


@app.route('/googleSignin', methods=['GET', 'POST'])
def googleSignin():
    # print(session)
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        # print(session)
        resp = google.get("/oauth2/v2/userinfo")
        assert resp.ok, resp.text
        post = users.query.filter_by(email=resp.json()["email"]).first()
        if not post:
            post = users(username=resp.json()["name"], email=resp.json()["email"])  # (name="Annie", email="something@gmail")
            print(post)
            db.session.add(post)
            db.session.commit()
    except InvalidClientIdError:
        print("error");
        session.clear()
        return render_template('main.html')

    return render_template('facebook-google.html')

@app.route('/facebookSignin', methods=['GET', 'POST'])
def facebookSignin():
    if not facebook.authorized:
        return redirect(url_for("facebook.login"))
    try:
        # print(session)
        resp=facebook.get('/me?fields=id,name,email')
        post = users.query.filter_by(email=resp.json()["email"]).first()
        if not post:
            post = users(username=resp.json()["name"], email=resp.json()["email"])  # (name="Annie", email="something@gmail")
            print(post)
            db.session.add(post)
            db.session.commit()
    except InvalidClientIdError:
        session.clear()
        print("error");
        return render_template('main.html')
    return render_template('facebook-google.html')

if __name__ == '__main__':
    app.run(debug=True)
