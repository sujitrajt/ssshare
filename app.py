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
# Cloud Deployment Link : https://ssshare.azurewebsites.net/ 
# https://flask-admin.readthedocs.io/en/latest/introduction/
# https://danidee10.github.io/2016/11/14/flask-by-example-7.html
# https://www.youtube.com/watch?v=71EU8gnZqZQ&ab_channel=ArpanNeupane
# https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial
# https://tutorial101.blogspot.com/2021/04/python-flask-upload-and-display-image.html
# https://stackoverflow.com/questions/44926465/upload-image-in-flask
# https://flask-bcrypt.readthedocs.io/en/1.0.1/
# https://www.rithmschool.com/courses/intermediate-flask/hashing-passwords-flask
# https://stackoverflow.com/questions/31358578/display-image-stored-as-binary-blob-in-template
# https://www.youtube.com/watch?v=I9BBGulrOmo&t=369s&ab_channel=Cairocoders
# https://www.youtube.com/watch?v=JDKmLB_HpTQ&t=258s&ab_channel=DawoodIddris
# https://www.youtube.com/watch?v=UIJKdCIEXUQ&t=1794s&ab_channel=CoreySchafer
# https://www.youtube.com/watch?v=gHfUt-N2_Jw&t=637s&ab_channel=CodeJana
# https://stackoverflow.com/questions/37031399/change-model-representation-in-flask-admin-without-modifying-model
# https://flask-admin.readthedocs.io/en/latest/introduction/#getting-started
# https://ckraczkowsky.medium.com/building-a-secure-admin-interface-with-flask-admin-and-flask-security-13ae81faa05
# https://stackoverflow.com/questions/20431572/how-to-reference-a-modelview-in-flask-admin
# https://www.youtube.com/watch?v=iIhAfX4iek0&t=661s&ab_channel=TechWithTim
# https://www.youtube.com/watch?v=FEyNt9iFPGc&ab_channel=PrettyPrinted
# https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
# https://github.com/Alexmod/Flask-User-and-Flask-admin
# https://www.youtube.com/watch?v=pPSZpCVRbvQ
# https://stackoverflow.com/questions/11017466/flask-to-return-image-stored-in-database

# instantiating the flask name
app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads/'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'city6528'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#Intiating an Admin View
admin = Admin(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#Allowed Extensions
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
#reference used : https://tutorial101.blogspot.com/2021/04/python-flask-upload-and-display-image.html
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
# reference used : https://flask-admin.readthedocs.io/en/latest/introduction/
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

#Adding admin view to the website and creating a session
admin.add_view(Controller(User,db.session))

#Register Form Model with column name, username,passoword
class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Please enter your name"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Please enter your username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Plese Type in your password"})
    submit = SubmitField('Register')
    # https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial
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

# home route 
@app.route('/')
def home():
    return render_template('home.html')

#Loging endpoint
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
        #checking the file type only if the file type is valid it will be uploaded into the database
        if image and allowed_file(image.filename):
            upload = Upload(filename=image.filename, data=image.read())
            db.session.add(upload)
            db.session.commit()
            return redirect(url_for('imageGroup'))
        else :
            return abort(404)
            # flash("Upload a Image file only")
            # return redirect(url_for('imageupload'))
        # return render_template('imgdownload.html')


@app.route('/createGroup',methods = ['POST','GET'])
@login_required
def createGroup():
    if request.method == 'GET':
        return render_template('createGroup.html')
    if request.method == 'POST':
        # fetching all the details of the group
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
            flash('Please select image to enter into image group')
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


@app.route('/download', methods=["GET", "POST"])
@login_required
def download():
    imageDetails = []
    if request.method == 'GET':
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("select id,filename from upload")
        rs = cursor.fetchall()
        for i in rs : 
            id=i[0]
            filename=i[1]
            print(id,filename)
            imageDetails.append([id,filename])
        return render_template('downloadImage.html',imgDetails = imageDetails)
    if request.method == "POST":
        imageSelected = request.form['imageSelected']
        print(imageSelected)
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("select * from upload where id = ?",[imageSelected])
        rs = cursor.fetchall()
        print(rs)
        print("IN DATABASE FUNCTION ")
        # c = cursor.execute(""" SELECT * FROM  upload where id """)
        # rs = c.fetchall()
        # print(rs)
        for i in rs:
            id=i[0]
            filename=i[1]
            data = i[2]
        print(id)
        conn.commit()
        # https://stackoverflow.com/questions/11017466/flask-to-return-image-stored-in-database
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
    # https://stackoverflow.com/questions/31358578/display-image-stored-as-binary-blob-in-template

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
        #hashing the password to store it in database
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        # adding user to database as well as creating a session to that user. 
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/imageUpload',methods = ['POST','GET'])
@login_required
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
            flash('Accepted image types are - png, jpg, jpeg, gif')
        # return redirect(request.url)

@app.route('/imageGroup',methods = ['POST','GET'])
@login_required
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
@login_required
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
