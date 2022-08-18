from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField 
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from flask_login import (UserMixin, login_user, LoginManager, 
						 login_required, logout_user, current_user)

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime
from pytz import timezone


app = Flask(__name__)

app.config['SECRET_KEY'] = "secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)



##################################################################
#Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))





##################################################################
#The Models
class Users(db.Model, UserMixin):
	tz = timezone('Asia/Ho_Chi_Minh')

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50), nullable=False)
	email = db.Column(db.String(100), unique=True)
	favorite_color = db.Column(db.String(50))
	date_added = db.Column(db.DateTime, default=datetime.now(tz))

	password_hash = db.Column(db.String(128))

	@property
	def password(self):
		raise AttributeError('password is not readable')
	
	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)


	#Create a string
	def __repr__(self):
		return '<Name %r>' % self.name



class Posts(db.Model):
	tz = timezone('Asia/Ho_Chi_Minh')

	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(50), nullable=False)
	content = db.Column(db.Text)
	author = db.Column(db.String(50))
	date_posted = db.Column(db.DateTime, default=datetime.now(tz))
	slug = db.Column(db.String(255))

###################################################################
#The Form classes
class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])	
	email = StringField("Email", validators=[DataRequired()])
	favorite_color = StringField("Favourite colour")
	password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('confirm_password', message='Please check your password')])
	confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])	
	submit = SubmitField("Submit")


class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = StringField("Content", validators=[DataRequired()], widget=TextArea())
	author = StringField("Author", validators=[DataRequired()])
	slug = StringField("Slug", validators=[DataRequired()])
	submit = SubmitField("Submit")


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])	
	password = PasswordField("Enter password", validators=[DataRequired()])
	submit = SubmitField("Submit")


class NamerForm(FlaskForm):
	name = StringField("What is your name?", validators=[DataRequired()])
	submit = SubmitField("Submit")



###################################################################
#The Routes
@app.route('/')
def index():
	tz = timezone('Asia/Ho_Chi_Minh')
	date = datetime.now(tz).strftime("%Y, %b %d")
	time = datetime.now(tz).strftime("%H:%M:%S")
	return render_template("index.html", date=date, time=time)



@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
	name = None

	form = UserForm()
	if form.validate_on_submit():

		user = Users.query.filter_by(email=form.email.data).first()
		if user is None:

			hashed_pw = generate_password_hash(form.password_hash.data, "sha256")

			user = Users(name=form.name.data, 
						 username=form.username.data,
						 email=form.email.data,
						 favorite_color=form.favorite_color.data,
						 password_hash=hashed_pw)
			db.session.add(user)
			db.session.commit()

			name = form.name.data 
			flash(f"{name} added successfully!")
		else:
			flash(f"Email already exists")

		form.name.data = ''
		form.username.data = ''
		form.email.data = ''
		form.favorite_color.data = ''
		form.password_hash.data = ''
		form.confirm_password.data = ''

	our_users = Users.query.order_by(Users.date_added)
	return render_template("add_user.html", 
							form=form,
							name=name,
							our_users=our_users)



@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
	form = UserForm()
	name_to_update = Users.query.get_or_404(id)

	if request.method == 'POST': 
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.favorite_color = request.form['favorite_color']
		try:

			db.session.commit()
			flash("User updated successfully!")
			return render_template("update.html",
									form=form,
									name_to_update=name_to_update)

		except:
			flash("Error! Something went wrong with update attempt")
			return render_template("update.html",
									form=form,
									name_to_update=name_to_update)

	else:
		return render_template("update.html",
								form=form,
								name_to_update=name_to_update)		


@app.route('/delete/<int:id>')
@login_required
def delete(id):
	name = None
	form = UserForm()

	user_to_delete = Users.query.get_or_404(id)
	try:
		db.session.delete(user_to_delete)
		db.session.commit()
		flash('User deleted successfully!')

		our_users = Users.query.order_by(Users.date_added)
		return render_template("add_user.html", 
								form=form,
								name=name,
								our_users=our_users)
	except:
		flash('Whoops! Something went wrong. Please try again, and let me know if problem persists')
		our_users = Users.query.order_by(Users.date_added)
		return render_template("add_user.html", 
								form=form,
								name=name,
								our_users=our_users)


@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
	form = PostForm()
	if form.validate_on_submit():
		post = Posts(title=form.title.data,
					 content= form.content.data,
					 author=form.author.data,
					 slug=form.slug.data)
		form.title.data = ''
		form.content.data = ''
		form.author.data = ''
		form.slug.data = ''

		db.session.add(post)
		db.session.commit()

		flash('Blog post submitted successfully!')

	return render_template('add_post.html', form=form)


@app.route('/all_posts/')
def all_posts():
	posts = Posts.query.order_by(Posts.date_posted)
	return render_template('all_posts.html', posts=posts)


@app.route('/post/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	date = post.date_posted.strftime('%Y, %b %d, %H:%M:%S')
	return render_template('post.html', post=post, date=date)	


@app.route('/post/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
	post = Posts.query.get_or_404(id)
	form = PostForm()	
	if form.validate_on_submit():
		post.title = form.title.data
		post.author = form.author.data
		post.slug = form.slug.data
		post.content = form.content.data 

		db.session.add(post)
		db.session.commit()
		flash('Post has been updated!')
		return redirect(url_for('post', id=post.id))

	form.title.data = post.title
	form.author.data = post.author
	form.slug.data = post.slug
	form.content.data = post.content
	return render_template('edit_post.html', form=form, id=post.id)


@app.route('/delete_post/<int:id>')
@login_required
def delete_post(id):
	post = Posts.query.get_or_404(id)
	try:
		db.session.delete(post)
		db.session.commit()
		flash('Post has been deleted!')
		return redirect(url_for('all_posts'))

	except:
		flash('Something went wrong :/ Please try again later')
		return redirect(url_for('all_posts'))


@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user:
			password_check = check_password_hash(user.password_hash, 
												form.password.data)
			if password_check:
				form.password.data = ''
				form.username.data = ''
				login_user(user)

				flash("You're logged in!")
				return redirect(url_for('index'))

			else:
				flash("Password doesn't match in database")
				form.password.data = ''

		else:
			flash("Username doesn't exist in database")
			form.username.data = ''

	return render_template('login.html', form=form)



@app.route('/logout')
def logout(user):
	logout_user(user)
	flash("You're logged out!")
	return redirect(url_for('index'))


@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404


@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500




