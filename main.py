from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

login_manager = LoginManager()
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    if not os.path.exists(DB_PATH):
        db.create_all()
        print("Database created.")
    else:
        print("Database already exists.")


# Retrieving user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data from the request object
        name = request.form['name']
        email = request.form['email']
        result = db.session.execute(db.select(User).where(User.email == email))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        password = request.form['password']
        hash_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        new_user = User(
            email=email,
            password=hash_password,
            name=name
        )
        db.session.add(new_user)
        try:
            db.session.commit()
            login_user(new_user)
        except IntegrityError as e:
            print(f"Error: {str(e)}")
            db.session.rollback()
            flash(f'error: {e}')
            return redirect(url_for("home"))

        return redirect(url_for('secrets', username=name))
    else:
        # If the request is GET, render the registration form template
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
        elif not user:
            flash("This email doesn't exist. Please try again.")
            return redirect('login')
        elif not check_password_hash(user.password, password):
            flash("Wrong password. Please try again.")
            return redirect('login')
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    FILE = os.path.join(os.path.dirname(__file__), "static/files/")
    filename = "cheat_sheet.pdf"
    # Check if the requested file exists in the download directory
    if os.path.exists(os.path.join(FILE, filename)):
        # Serve the requested file for download
        return send_from_directory(FILE, filename, as_attachment=True)
    else:
        # Handle the case where the file doesn't exist
        return "File not found", 404


if __name__ == "__main__":
    app.run(debug=True)
