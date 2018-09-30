from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
db = SQLAlchemy(app)

app.secret_key = "helpmerecipe"
blueprint = make_google_blueprint(
    client_id="640840633381-8rrcgg5r9hru2al5e853jq95valimmd5.apps.googleusercontent.com",
    client_secret="YvDSgKVfGEM_nLblFbBPESZp",
    scope=[
        "https://www.googleapis.com/auth/plus.me",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
    offline=True,
)
class users(db.Model):
    name = db.Column(db.Unicode, primary_key = True)
    email = db.Column(db.Unicode)

app.register_blueprint(blueprint, url_prefix="/login")
@app.route('/',methods=['GET','POST'])
def index():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        post = users(name=username,email=password)

        db.session.add(post)
        db.session.commit()

    return render_template('main.html')

@app.route('/facebook-google')
def fglogin():
    return render_template('facebook-google.html')

@app.route('/googleSignin', methods=['GET','POST'])
def googleSignin():
    #print(session)
    if not google.authorized:
        return redirect(url_for("google.login"))
    try:
        #print(session)
        resp = google.get("/oauth2/v2/userinfo")
        assert resp.ok, resp.text
        post = users(name=resp.json()["name"], email=resp.json()["email"])#(name="Annie", email="something@gmail")
        print(post)
        db.session.add(post)
        db.session.commit()
    except InvalidClientIdError:
        session.clear()
        return render_template('main.html')

    return render_template('facebook-google.html')

if __name__ == '__main__':
    app.run(debug=True)
