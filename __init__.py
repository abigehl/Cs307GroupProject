from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():

    return render_template('main.html')

@app.route('/facebook-google')
def fglogin():
    return render_template('facebook-google.html')

if __name__ == '__main__':
    app.run(debug=True)

hi annie