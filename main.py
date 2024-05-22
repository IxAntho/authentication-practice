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


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


DB_PATH = os.path.join(os.path.dirname(__file__), "posts.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model):
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


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data from the request object
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(
            email=email,
            password=password,
            name=name
        )
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError as e:
            print(f"Error: {str(e)}")
            db.session.rollback()

        return redirect(url_for('secrets', username=name))
    else:
        # If the request is GET, render the registration form template
        return render_template('register.html')


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    name = request.args.get('username')
    return render_template("secrets.html", username=name)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    pass


if __name__ == "__main__":
    app.run(debug=True)
