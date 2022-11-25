from flask import Flask, render_template, url_for, redirect, request , Response , send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user , current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
# from flask_admin import Admin
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from io import BytesIO
import sqlite3
from base64 import b64encode
# from db import intialDb,db


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'

app.config['SECRET_KEY'] = 'city6528'



admin = Admin(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean,default = False)

class Controller(ModelView):
    def is_accessible(self):
        print("hello",current_user.is_admin)
        if current_user.is_admin == True:
            return current_user.is_authenticated
        else:
            return abort(404)

    def not_auth(self):
        return "Access Denied"

admin.add_view(Controller(User,db.session))


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Please enter your name"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Please enter your username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Plese Type in your password"})
    submit = SubmitField('Register')

    def check_user(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            ValidationError('That username already exists. Please choose a different one.')
            return redirect(url_for('login'))

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# class imageUpload(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     img = db.Column(db.Text, unique=True, nullable=False)
#     name = db.Column(db.Text, nullable=False)
#     mimetype = db.Column(db.Text, nullable=False)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # form2 = RegisterForm()
    uname=form.username.data
    print(uname)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template('dashboard.html',name = uname)
                # return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/imguploadPage',methods = ['GET','POST'])
@login_required
def imguploadPage():
    return render_template('imguploadPage.html')

@app.route('/imageupload',methods = ['POST','GET'])
@login_required
def imageupload():
    if request.method == 'GET':
        return render_template('imguploadPage.html')
    if request.method == 'POST':
        # print("hellow world")
        image = request.files['image']
        print(image)
        if not image: 
            return 'Please enter a valid Photo'
        # file_name = secure_filename(image.filename)
        # mimetype = image.mimetype
        # if not file_name or not mimetype:
        #     return "Bad file type"
        upload = Upload(filename=image.filename, data=image.read())
        db.session.add(upload)
        db.session.commit()

        # return 'Img Uploaded!', 200
        return render_template('imgdownload.html')


# @app.route('/download/<int:id>')
# @login_required
# def viewimage(id):
#     upload = Upload.query.filter_by(id=id).first()
#     return send_file(BytesIO(upload.data), attachment_filename=upload.filename, as_attachment=True)

@app.route('/download', methods=["GET", "POST"])
def download():
    if request.method == "POST":

        conn= sqlite3.connect("database.db")
        cursor = conn.cursor()
        print("IN DATABASE FUNCTION ")
        c = cursor.execute(""" SELECT * FROM  upload """)
        rs = c.fetchall()
        # print(rs)
        for i in rs:
            id=i[0]
            filename=i[1]
            data = i[2]
        print(id)

        conn.commit()
        cursor.close()
        conn.close()

        return send_file(BytesIO(data), attachment_filename=filename, as_attachment=True)


    return render_template("viewImg.html",rs=rs)

@app.route('/viewImg/<int:id>',methods=['GET','POST'])
@login_required
def viewImg(id):
    # obj = Upload.query(Upload.id == id).fetch(1)[0]
    conn= sqlite3.connect("database.db")
    cursor = conn.cursor()
    print(id)
    cursor.execute("SELECT * FROM upload WHERE id = ?",(id,))
    for x in cursor.fetchall():
        filename=x[1]
        data=x[2]
        break
    image = b64encode(data).decode("utf-8")
    return render_template("viewImg.html", image=image)


# @app.route('/<int:id>')
# def viewimage(id):
#     img = Upload.query.filter_by(id=id).first()
#     if not img:
#         return 'Img Not Found!', 404

#     return Response(img.filename)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
