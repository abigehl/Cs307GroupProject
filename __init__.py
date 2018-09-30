from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://helpmerecipe:passpass@helpmerecipe.coy90uyod5ue.us-east-2.rds.amazonaws.com/helpmerecipe'
db = SQLAlchemy(app)


class users(db.Model):
    name = db.Column(db.Unicode, primary_key = True)
    email = db.Column(db.Unicode)

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


if __name__ == '__main__':
    app.run(debug=True)
