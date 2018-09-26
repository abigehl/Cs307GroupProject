from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('main.html');
    #return "<h2>First Main Deploy!</h2>"
    
if __name__ == '__main__':
    app.run(debug=True)
