##################################################################
#INDEX

#	1. Import library
#	2. Create App
#	3. Login Manager
#	4. Models
#	5. Forms
#	6. User routes
#	7. Post routes
#	8. Search function
#	9. Error routes






								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










##################################################################
#Import library

from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import (StringField, SubmitField, PasswordField, 
					 BooleanField) 
from wtforms.validators import DataRequired, EqualTo, Length
from flask_ckeditor import CKEditor, CKEditorField

from flask_login import (UserMixin, login_user, LoginManager, 
						 login_required, logout_user, current_user)

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid as uuid
import os

from datetime import datetime
import pytz






								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










##################################################################
#Create App

app = Flask(__name__)

app.config['SECRET_KEY'] = "secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
#'postgresql://dlyegtyeuffupk:dcf8b09b981a8781ebfee848ec1dc7f180950c1fea6fec39bf4bbbd5a7c03d80@ec2-54-228-125-183.eu-west-1.compute.amazonaws.com:5432/da69lhjv2b3li'
#'sqlite:///users.db'

UPLOAD_FOLDER = "static/images/"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
migrate = Migrate(app, db)
ckeditor = CKEditor(app)





								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










##################################################################
#Login Manager

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))






								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










##################################################################
#The Models

class Posts(db.Model):

	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(50), nullable=False)
	content = db.Column(db.Text)
	date_posted = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Ho_Chi_Minh')))
	slug = db.Column(db.String(255))

	#Create foreign key to link users to their posts
	poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Users(db.Model, UserMixin):

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(50), unique=True)
	name = db.Column(db.String(50), nullable=False)
	email = db.Column(db.String(100), unique=True)
	favorite_color = db.Column(db.String(50))
	date_added = db.Column(db.DateTime, default=datetime.now(pytz.timezone('Asia/Ho_Chi_Minh')))
	profile_pic = db.Column(db.String(), nullable=True)
	password_hash = db.Column(db.String(128))

	# User can have many posts
	posts = db.relationship('Posts', backref='poster')

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







								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










###################################################################
#The Form classes

class UserForm(FlaskForm):
	name = StringField("Name", validators=[DataRequired()])
	username = StringField("Username", validators=[DataRequired()])	
	email = StringField("Email", validators=[DataRequired()])
	favorite_color = StringField("Favourite colour")
	password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('confirm_password', message='Please check your password')])
	confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])	
	profile_pic = FileField("Profile Pic")
	submit = SubmitField("Submit")


class PostForm(FlaskForm):
	title = StringField("Title", validators=[DataRequired()])
	content = CKEditorField("Content", validators=[DataRequired()])
	slug = StringField("Slug", validators=[DataRequired()])
	submit = SubmitField("Submit")


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])	
	password = PasswordField("Enter password", validators=[DataRequired()])
	submit = SubmitField("Submit")


class SearchForm(FlaskForm):
	searched = StringField("Searched", validators=[DataRequired()])
	submit = SubmitField("Submit")

@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)




								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










###################################################################
#User Routes

@app.route('/')
def index():
	tz = pytz.timezone('Asia/Ho_Chi_Minh')
	date = datetime.now(tz).strftime("%Y, %b %d")
	time = datetime.now(tz).strftime("%H:%M:%S")
	return render_template("index.html", date=date, time=time)


@app.route('/admin')
@login_required
def admin():
	if current_user.id == 1:
		users = Users.query.all()
		posts = Posts.query.all()
		return render_template("admin.html", users=users, posts=posts)
	else:
		flash("Unfortunately only admin can access admin page")		
		return redirect(url_for('index'))


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
						 password_hash=hashed_pw,
						 date_added=datetime.now(pytz.timezone('Asia/Ho_Chi_Minh')))

			try:
				db.session.add(user)
				db.session.commit()

				name = form.name.data 

				form.name.data = ''
				form.username.data = ''
				form.email.data = ''
				form.favorite_color.data = ''
				form.password_hash.data = ''
				form.confirm_password.data = ''

				flash(f"{name} added successfully!")
				return redirect(url_for('login'))

			except:
				flash(f"Whoops! Something went wrong. Please try again")				

		else:
			flash(f"Email already exists")

		form.name.data = ''
		form.username.data = ''
		form.email.data = ''
		form.favorite_color.data = ''
		form.password_hash.data = ''
		form.confirm_password.data = ''

	return render_template("add_user.html", form=form)


@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
	name = None
	form = UserForm()

	user_to_delete = Users.query.get_or_404(id)
	if user_to_delete.id == current_user.id or current_user.id == 1:
		try:
			db.session.delete(user_to_delete)
			db.session.commit()

			logout_user()

			flash('User deleted successfully!')
			return render_template("index.html")

		except:
			flash('Whoops! Something went wrong. Please try again, and let me know if problem persists')
			return render_template("index.html")


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
				return redirect(url_for('dashboard'))

			else:
				flash("Password doesn't match in database")
				form.password.data = ''

		else:
			flash("Username doesn't exist in database")
			form.username.data = ''

	return render_template('login.html', form=form)


@app.route('/logout')
def logout():
	logout_user()
	flash("You're logged out!")
	return redirect(url_for('index'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
	
	form = UserForm()
	id = current_user.id
	name_to_update = Users.query.get_or_404(id)

	if request.method == 'POST': 
		name_to_update.username = request.form['username']
		name_to_update.name = request.form['name']
		name_to_update.email = request.form['email']
		name_to_update.favorite_color = request.form['favorite_color']

		profile_pic_upload = request.files['profile_pic']

		pic_filename = secure_filename(profile_pic_upload.filename)
		pic_name = str(uuid.uuid1()) + "_" + pic_filename
		name_to_update.profile_pic = pic_name

		profile_pic_upload.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))

		try:
			db.session.commit()
			flash("User updated successfully!")
			return render_template("dashboard.html",
									form=form,
									name_to_update=name_to_update)

		except:
			flash("Error! Something went wrong with update attempt")
			return render_template("dashboard.html",
									form=form,
									name_to_update=name_to_update)


	return render_template("dashboard.html",
							form=form,
							name_to_update=name_to_update)
	return render_template('dashboard.html',
							form=form,
							name_to_update=name_to_update)






								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










###################################################################
#Post Routes

@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
	form = PostForm()

	if form.validate_on_submit():

		poster = current_user.id

		post = Posts(title=form.title.data,
					 content= form.content.data,
					 poster_id=poster,
					 slug=form.slug.data,
					 date_posted=datetime.now(pytz.timezone('Asia/Ho_Chi_Minh')))
		form.title.data = ''
		form.content.data = ''
		form.slug.data = ''

		db.session.add(post)
		db.session.commit()

		flash('Blog post submitted successfully!')

	return render_template('add_post.html', form=form)


@app.route('/all_posts/')
def all_posts():
	posts = Posts.query.order_by(Posts.date_posted)
	return render_template('all_posts.html', posts=posts)


#Specific Post
@app.route('/post/<int:id>')
def post(id):
	post = Posts.query.get_or_404(id)
	date = post.date_posted.strftime('%Y, %b %d, %H:%M:%S')
	return render_template('post.html', post=post, date=date)	


#Specific Post - Edit
@app.route('/post/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
	post = Posts.query.get_or_404(id)
	if post.poster.id == current_user.id:
		form = PostForm()	
		if form.validate_on_submit():
			post.title = form.title.data
			post.slug = form.slug.data
			post.content = form.content.data 

			try:
				db.session.add(post)
				db.session.commit()
				flash('Post has been updated!')
				return redirect(url_for('post', id=post.id))

			except:
				flash('Something went wrong :/ Please try again later')
				return redirect(url_for('post', id=post.id))

		form.title.data = post.title
		form.slug.data = post.slug
		form.content.data = post.content
		return render_template('edit_post.html', form=form, id=post.id)

	else:
		return redirect(url_for('all_posts'))		


#Specific Post - Delete
@app.route('/delete_post/<int:id>')
@login_required
def delete_post(id):
	post = Posts.query.get_or_404(id)
	try:
		if post.poster.id == current_user.id:
			try:
				db.session.delete(post)
				db.session.commit()
				flash('Post has been deleted!')
				return redirect(url_for('all_posts'))

			except:
				flash('Something went wrong :/ Please try again later')
				return redirect(url_for('all_posts'))

		else:
				return redirect(url_for('all_posts'))

	except:
		if current_user.id == 1:
			try:
				db.session.delete(post)
				db.session.commit()
				flash('Post has been deleted!')
				return redirect(url_for('all_posts'))

			except:
				flash('Something went wrong :/ Please try again later')
				return redirect(url_for('all_posts'))

		else:
			return redirect(url_for('all_posts'))





								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










###################################################################
#Search function
@app.route('/search', methods=['POST'])
def search():
	form = SearchForm()
	posts = Posts.query

	if form.validate_on_submit():
		post.searched = form.searched.data
		
		posts = posts.filter(Posts.title.like('%' + post.searched + '%'))
		posts = posts.order_by(Posts.title).all()

		return render_template('searched.html', form=form, 
												searched = post.searched,
												posts=posts)

#





								#
							#	#	#
						#	#	#	#	#
					#	#	#	#	#	#	#
						#	#	#	#	#
							#	#	#
								#










###################################################################
#Error Routes
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404


@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500




