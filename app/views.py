from app import app, lm
from flask import request, redirect, render_template, url_for, flash
from flask.ext.login import login_user, logout_user, login_required
from .forms import LoginForm
from .user import User
from werkzeug.security import generate_password_hash

@app.route('/')
@login_required
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    collection = app.config['USERS_COLLECTION']
    if request.method == 'POST' and form.validate_on_submit():
        user = collection.find_one({"username": form.username.data})
        if user and User.validate_login(user['password'], form.password.data):
            user_obj = User(user['username'])
            login_user(user_obj)
            flash("Logged in successfully!", category='success')
            return redirect(request.args.get("next") or url_for("home"))
        flash("Wrong username or password!", category='error')
    return render_template('login.html', title='login', form=form)

@app.route('/signup', methods= ['GET', 'POST'])
def signup():
    collection = app.config['USERS_COLLECTION']
    form = LoginForm()
    username = form.username.data
    password = form.password.data
    if request.method == 'POST' and form.validate_on_submit():
        pass_hash = generate_password_hash(password, method='pbkdf2:sha256')
        # Insert the user in the DB
        user = collection.find_one({"username": username})
        if user:
            flash("User already exists!", category='error')
        else:
            collection.insert({"username": username, "password": pass_hash})
            flash("Signed up successfully! Login to continue.", category='success')
    return render_template('signup.html', title = 'signup', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    return render_template('chat.html')


@app.route('/schedules', methods=['GET', 'POST'])
@login_required
def schedules():
    return render_template('schedules.html')



@lm.user_loader
def load_user(username):
    u = app.config['USERS_COLLECTION'].find_one({"username": username})
    if not u:
        return None
    return User(u['username'])
