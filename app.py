from itsdangerous import URLSafeTimedSerializer
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import random, os
from dotenv import load_dotenv

DOMAIN = "https://dashboard.acoult.art"

app = Flask(__name__)

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(128), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.name)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        verification_code_plain = str(random.randint(100000, 999999))
        verification_code_hashed = generate_password_hash(verification_code_plain, method='pbkdf2:sha256')
        
        user = User(email=email, name=name, password=password, verification_code=verification_code_hashed)
        db.session.add(user)
        db.session.commit()
        
        msg = Message('Verify Your Account', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your verification code is {verification_code_plain}'
        mail.send(msg)


        session['email'] = email
        return redirect(url_for('verify'))

    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'email' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        code = request.form['code']
        user = User.query.filter_by(email=session['email']).first()

        if user and check_password_hash(user.verification_code, code):
            user.verified = True
            user.verification_code = None
            db.session.commit()
            flash('Account verified! You can now log in.', 'success')
            return redirect(url_for('login'))

        flash('Invalid code', 'danger')

    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            if not user.verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('verify'))

            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user and user.verified:
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = f"{DOMAIN}{url_for('reset_password', token=token)}"

            msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_link}'
            mail.send(msg)

            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email not found or not verified.', 'danger')

        return redirect(url_for('forgot_password'))

    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            new_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
            user.password = new_password
            db.session.commit()
            flash('Password successfully reset! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset.html')

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form['password']

    # Check if password is correct
    if not check_password_hash(current_user.password, password):
        flash("Incorrect password. Account not deleted.", "danger")
        return redirect(url_for('dashboard'))

    # Delete user from the database
    db.session.delete(current_user)
    db.session.commit()

    # Log out the user
    logout_user()
    flash("Your account has been deleted.", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    from waitress import serve
    serve(app, port=5003, host="0.0.0.0")
