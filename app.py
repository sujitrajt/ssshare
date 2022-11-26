from flask import Flask, render_template, url_for, redirect, request , Response , send_file, abort, flash
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
import os
# from db import intialDb,db

#References 
# https://flask-admin.readthedocs.io/en/latest/introduction/
# https://danidee10.github.io/2016/11/14/flask-by-example-7.html
# https://www.youtube.com/watch?v=71EU8gnZqZQ&ab_channel=ArpanNeupane
# https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial
# https://tutorial101.blogspot.com/2021/04/python-flask-upload-and-display-image.html
# https://stackoverflow.com/questions/44926465/upload-image-in-flask
# https://flask-bcrypt.readthedocs.io/en/1.0.1/
# https://www.rithmschool.com/courses/intermediate-flask/hashing-passwords-flask
app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads/'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'

app.config['SECRET_KEY'] = 'city6528'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

admin = Admin(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# USER MODEL DATABASE with id , username and passowrd
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean,default = False)

# class UserGroup(db.Model, UserMixin):
#     id = db.Column(db.Integer)
#     username = db.Column(db.String(20),nullable=False, unique=True)
#     is_text = db.Column(db.Boolean,default = False)


#overiding model view controller to check if the user is an admin or not
class Controller(ModelView):
    def is_accessible(self):
        print("hello",current_user.is_admin)
        if current_user.is_admin == True:
            print("hello world",current_user.is_authenticated)
            return current_user.is_authenticated
        else:
            return abort(404)

    def not_auth(self):
        return "Access Denied"

admin.add_view(Controller(User,db.session))

#Register Form Model with column name, username,passoword
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

#loginform model with column username password and submit
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# class imageUpload(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     img = db.Column(db.Text, unique=True, nullable=False)
#     name = db.Column(db.Text, nullable=False)
#     mimetype = db.Column(db.Text, nullable=False)

#Upload model with id , filename and data , data is stored as blob data
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
        #quering the user model to get the user details from the database
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            #check password
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


@app.route('/createGroup',methods = ['POST','GET'])
@login_required
def createGroup():
    if request.method == 'GET':
        return render_template('createGroup.html')
    if request.method == 'POST':
        groupName = request.form["groupName"]
        groupDesc = request.form['groupDesc']
        userName = current_user.username
        print("groupName",groupName)
        print("group Desc",groupDesc)
        print("userName",userName)
        conn= sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("INSERT into grp (groupName,groupDesc,userName) VALUES (?,?,?)",[groupName,groupDesc,userName])
        conn.commit()
        return render_template('dashboard.html')

@app.route('/viewGroup',methods =['POST','GET'])
@login_required
def viewGroup():
    grp = []
    if request.method == 'GET':
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        userName = current_user.username
        c.execute("select * from grp where (userName) = (?)" ,[userName])
        rs = c.fetchall()
        print("hellp",rs)
        if rs  == []:
            flash('Please create a group or join group')
            return render_template('dashboard.html') 
        else :
            for i in rs:
                groupName=i[0]
                groupDesc=i[1]
                username = i[2]
                print(groupName,groupDesc,username)
                grp.append([groupName,groupDesc,username])
            return render_template('showGroup.html',groupDetails = grp)
    if request.method == 'POST' :
        selectGroup = request.form["groupSelected"]
        print(selectGroup)
        if selectGroup == 'Image':
            return redirect(url_for('imageGroup'))
        else :
            return render_template('dashboard.html')

@app.route('/joinGroup',methods = ['POST','GET'])
@login_required
def joinGroup():
    grpDetails = []
    if request.method == 'GET':
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        userName = current_user.username
        c.execute("select * from grp")
        rs = c.fetchall()
        for i in rs: 
            groupName=i[0]
            groupDesc=i[1]
            username = i[2]
            print(groupName,groupDesc,username)
            grpDetails.append([groupName,groupDesc,username])
        print("groups available",grpDetails)
        return render_template('joingroup.html',grp = grpDetails)
    if request.method == 'POST':
        groupName = request.form["groupSelected"]
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        user_name = current_user.username
        c.execute("INSERT into grp (groupName,userName) VALUES (?,?)",[groupName,user_name])
        conn.commit()
        return render_template('dashboard.html')
        



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

@app.route('/imageUpload',methods = ['POST','GET'])
def imageUpload():
    if request.method == 'GET':
        return render_template('imageUpload.html')
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return render_template('imageUpload.html')
        file = request.files['file']
        if file.filename == '':
            flash('No image selected for uploading')
            return render_template('imageUpload.html')
        if file and allowed_file(file.filename):
            print("hello world",file)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('Image successfully uploaded')
            print("file uploaded successfully")
            return render_template('imageUpload.html')
        else:
            flash('Allowed image types are - png, jpg, jpeg, gif')
        # return redirect(request.url)

@app.route('/imageGroup',methods = ['POST','GET'])
def imageGroup():
    users = []
    if request.method == 'GET':
        conn= sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("select username from grp")
        rs = cursor.fetchall()
        for x in rs:
            username=x[0]
            users.append(username)
        print("list of users in the group",users)
        return render_template('ImageGroup.html',user = users)
    if request.method  == "POST":
        pass

@app.route('/showimage',methods = ['POST','GET'])
def showimage():
    imageDetails = []
    if request.method == 'GET':
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("select id,filename from upload")
        rs = cursor.fetchall()
        print(rs)
        for i in rs : 
            id=i[0]
            filename=i[1]
            print(id,filename)
            imageDetails.append([id,filename])
        return render_template('showimage.html',imgDetails = imageDetails)
    if request.method == 'POST':
        imageSelected = request.form['imageSelected']
        print(imageSelected)
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("select data from upload where id = ?",[imageSelected])
        rs = cursor.fetchall()
        for i in rs:
            imageData = i[0]
            break
        image = b64encode(imageData).decode("utf-8")
    return render_template("viewImg.html", image=image)


if __name__ == "__main__":
    app.run(debug=True)
