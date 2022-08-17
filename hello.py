from flask import Flask, render_template


app = Flask(__name__)


@app.route('/')
def index():
	favourite_pizza = ['Mexican', 'Chicken', 'Seasons', 'Cheese', 6789]
	return render_template("index.html", favourite_pizza=favourite_pizza)


@app.route('/user/<name>')
def user(name):
	return render_template("user.html", name=name)


@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500
