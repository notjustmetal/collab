from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from flask_moment import Moment
from flask_mail import Mail, Message as MailMessage
from time import time
import os, json, datetime, random, jwt

app = Flask(__name__, static_url_path='/static')
appdir = os.path.abspath(os.path.dirname(__file__))
login_manager = LoginManager(app)
login_manager.login_view = 'login'
moment = Moment(app)

app.config["SQLALCHEMY_DATABASE_URI"] = \
	f"sqlite:///{os.path.join(appdir, 'library.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['UPLOAD_FOLDER'] = os.path.join(appdir, './static/images/display_pictures')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '*****'
app.config['MAIL_PASSWORD'] = '*****'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

db = SQLAlchemy(app)
mail = Mail(app)

# Model for User
class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	username = db.Column(db.String, nullable=False)
	email = db.Column(db.String, nullable=False)
	password = db.Column(db.String, nullable=False)
	profile = db.relationship('Profile', backref='user', uselist=False)
	message = db.relationship('Message', backref='user')

	def get_reset_password_token(self, expires_in=600):
		return jwt.encode(
			{'reset_password': self.id, 'exp': time() + expires_in},
			app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

	@staticmethod
	def verify_reset_password_token(token):
		try:
			id = jwt.decode(token, app.config['SECRET_KEY'],
							algorithms=['HS256'])['reset_password']
		except:
			return
		return User.query.get(id)

# Model for Profile
class Profile(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	first_name = db.Column(db.String, nullable=False)
	last_name = db.Column(db.String, nullable=False)
	dob = db.Column(db.String, nullable=False)
	picture = db.Column(db.String, nullable=False)
	instruments = db.Column(db.String, nullable=False)
	genre = db.Column(db.String, nullable=False)
	about = db.Column(db.String, nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	message = db.relationship('Message', backref='profile')

# Model for Message
class Message(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	body = db.Column(db.String, nullable=False)
	timestamp = db.Column(db.DateTime(), default=datetime.datetime.utcnow(), index=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'))

db.create_all()

# Route for Landing Page
@app.route('/')
def landing():
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	user = User.query.filter_by(username='dodie').first()
	print(user.password)

	return render_template('index.html')

# Route for Log In Page
@app.route('/login', methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']

		currUser = User.query.filter_by(username=username).first()

		if currUser is None or not check_password_hash(currUser.password, password):
			flash('Invalid username or password.', 'alert-danger')
			return redirect(url_for('login'))

		login_user(currUser)
		return redirect(url_for('home'))

	return render_template('login.html', title='Log In')

# Route for Sign Up Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	if request.method == 'POST':
		username = request.form['username']
		email = request.form['email']
		password = generate_password_hash(request.form['password'])

		checkUserID = User.query.filter_by(username=username).first()
		checkUserEmail = User.query.filter_by(email=email).first()
		if checkUserID is not None or checkUserEmail is not None:
			flash('The username or email is already in use.')
			return redirect(url_for('signup'))

		user = User(username=username, email=email, password=password)
		db.session.add(user)
		db.session.commit()

		currentUser = User.query.filter_by(username=username).first()
		uid = currentUser.id
		login_user(currentUser)
		return redirect(url_for('createProfile', uid=uid, title='Create Profile'))

	return render_template('signup.html', title='Sign Up')

# Route for Forgot Password Page
@app.route('/forgot')
def forgot():
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	return render_template('forgot_password.html', title='Forgot Password')

# Route for Check Email Page
@app.route('/forgot/email')
def email():
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	email = request.args['email']
	user = User.query.filter_by(email=email).first()

	if not user:
		flash('Invalid email address.')
		return redirect(url_for('forgot'))

	token = user.get_reset_password_token()
	msg = MailMessage('[Collab] - Reset Your Passwrd', sender=app.config['MAIL_USERNAME'],
					 recipients=[email])
	msg.body = render_template('reset_password.txt', user=user, token=token)
	mail.send(msg)

	flash('Please check email for a password reset link.', 'alert-warning')
	return redirect(url_for('login'))

# Route for Reset Password Page
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	user = User.verify_reset_password_token(token)

	if not user:
		return redirect(url_for('index'))

	if request.method == 'POST':
		passwordNew = request.form['passwordNew']
		passwordRetype = request.form['passwordRetype']
		
		if (passwordNew != passwordRetype):
			flash('Passwords do not match.')
			return redirect(url_for('reset', token=token))

		user.password = generate_password_hash(passwordNew)
		db.session.commit()
		flash('Congratulations! Your password has been updated.', 'alert-success')
		return redirect(url_for('login'))

	return render_template('reset_password.html', title='Reset Password', token=token)

# Route for Create Profile Page
@app.route('/signup/<int:uid>', methods=['GET', 'POST'])
@login_required
def createProfile(uid):
	if request.method == 'POST':
		first_name = request.form['first_name']
		last_name = request.form['last_name']
		picture = request.files['picture']
		about = request.form['about']
		filename = str(uid) + ".jpg"
		picturePath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
		picture.save(picturePath)
		pictureDB = "../static/images/display_pictures/" + filename
		dob = request.form['month'] + " " + request.form['day'] + " " + request.form['year']
		instruments = request.form.getlist('instruments')
		instrumentString = ""

		for value in instruments:
			if value != instruments[len(instruments) - 1]:
				instrumentString = instrumentString + value + ", "
			else:
				instrumentString = instrumentString + value

		genres = request.form.getlist('genres')
		genreString = ""

		for value in genres:
			if value != genres[len(genres) - 1]:
				genreString = genreString + value + ", "
			else:
				genreString = genreString + value

		currentProfile = Profile(first_name=first_name, last_name=last_name, picture=pictureDB, 
								dob=dob, instruments=instrumentString, genre=genreString, about=about, 
								user=User.query.filter_by(id=uid).first())
		
		db.session.add(currentProfile)
		db.session.commit()
		return redirect(url_for('home'))

	if current_user.profile is not None:
		return redirect(url_for('home'))
	
	return render_template('create_profile.html', uid=uid, title='Create Profile')

# Route for Home Page
@app.route('/home')
@login_required
def home():
	profiles = Profile.query.all()
	random.shuffle(profiles)

	return render_template('home.html', profiles=profiles)

# Route for Profile Page
@app.route('/profile/<int:uid>', methods=['GET', 'POST'])
@login_required
def profile(uid):
	if request.method == 'POST':
		profile = Profile.query.filter_by(id=uid).first()
		profile.first_name = request.form['first_name']
		profile.last_name = request.form['last_name']
		profile.about = request.form['about']
		picture = request.files['picture']

		if picture:
			filename = str(uid) + ".jpg"
			picturePath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
			
			if os.path.exists(picturePath):
				os.remove(picturePath)

			picture.save(picturePath)

		profile.dob = request.form['month'] + " " + request.form['day'] + " " + request.form['year']
		instruments = request.form.getlist('instruments')
		instrumentString = ""

		for value in instruments:
			if value != instruments[len(instruments) - 1]:
				instrumentString = instrumentString + value + ", "
			else:
				instrumentString = instrumentString + value

		profile.instruments = instrumentString

		genres = request.form.getlist('genres')
		genreString = ""

		for value in genres:
			if value != genres[len(genres) - 1]:
				genreString = genreString + value + ", "
			else:
				genreString = genreString + value

		profile.genre = genreString
		db.session.commit()

		return redirect(url_for('profile', uid=uid))

	profile = Profile.query.filter_by(id=uid).first()
	instruments = profile.instruments.translate({ord(','): None}).split()
	genres = profile.genre.translate({ord(','): None}).split()

	message = profile.message
	author = []
	
	for each in message:
		author.append(User.query.filter_by(id=each.user_id).first())

	if profile is not None:
		return render_template('profile.html', title=profile.first_name + ' ' + profile.last_name, 
								profile=profile, instruments=instruments, genres=genres, author=author)

# Route for Edit Profile Page
@app.route('/profile/<int:uid>/edit')
@login_required
def editProfile(uid):
	profile = current_user.profile
	dob = profile.dob.split()
	instruments = profile.instruments.translate({ord(','): None}).split()
	genres = profile.genre.translate({ord(','): None}).split()

	if current_user.profile.id == uid:
		return render_template('edit_profile.html', uid=uid , profile=profile, dob=dob, 
								instruments=instruments, genres=genres , title='Edit Profile')

# Route for Message 
@app.route('/profile/<int:uid>/message', methods=['POST'])
@login_required
def message(uid):
	body = request.form['message']
	user_id = current_user
	profile_id = Profile.query.filter_by(id=uid).first()

	message = Message(body=body, timestamp=datetime.datetime.utcnow(), user=user_id, profile=profile_id)
	db.session.add(message)
	db.session.commit()

	return redirect(url_for('profile', uid=uid))

# Route for Delete Message
@app.route('/message/<int:uid>', methods=['POST'])
@login_required
def deleteMessage(uid):
	message = Message.query.filter_by(id=uid).first()
	profile = message.profile.id
	db.session.delete(message)
	db.session.commit()

	return redirect(url_for('profile', uid=profile))

# Route for Results Page
@app.route('/results', methods=['GET'])
@login_required
def results():
	query = request.args['q']
	look_for = '%{0}%'.format(query)
	nameResults = Profile.query.filter((Profile.first_name.like(look_for)) | (Profile.last_name.like(look_for))).all()
	instrumentResults = Profile.query.filter(Profile.instruments.like(look_for)).all()
	genreResults = Profile.query.filter(Profile.genre.like(look_for)).all()
		
	return render_template('results.html', title=query, nameResults=nameResults, instrumentResults=instrumentResults,
							genreResults=genreResults)

# Route for Log Out
@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('landing'))

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

if __name__ == "__main__":
	app.run(debug=True)