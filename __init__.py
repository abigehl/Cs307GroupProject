from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
<<<<<<< HEAD
    return render_template('main.html');
    #return "<h2>First Main Deploy!</h2>"
    
=======
    return render_template('main.html')

@app.route('/facebook-google')
def fglogin():
    return render_template('facebook-google.html')

>>>>>>> a115dc6a2fcff33cc6459aa82753d42b97729395
if __name__ == '__main__':
    app.run(debug=True)
