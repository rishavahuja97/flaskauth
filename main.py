from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)


app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register',methods = ['GET','POST'])
def register():
    if request.method == 'POST':
        new_user = User(
           email=request.form['email'],
           password=generate_password_hash(request.form['password'] , method='pbkdf2:sha256', salt_length=8),
           name=request.form['name']
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('secrets'))

    return render_template("register.html")


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user!=None:
            upassword = request.form['password']

            is_password_correct = check_password_hash(user.password,upassword)
            if is_password_correct:
                login_user(user)
                return redirect(url_for('secrets'))

            else:
                flash('Incorrect password try again')
                return render_template("login.html")


        else:
            flash('Entered email was not found please retry with different email')

            return render_template("login.html")
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html",logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static/files','cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
