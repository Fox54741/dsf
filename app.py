from flask import Flask, render_template, redirect, url_for, abort, request, jsonify
from flask_bootstrap import Bootstrap
from flask_uploads import UploadSet, IMAGES, configure_uploads
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, FloatField, IntegerField, FileField
from wtforms.validators import InputRequired, Email, Length, EqualTo, NumberRange 
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import json
import operator
import time
import datetime
import base64

import numpy
import cv2

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['UPLOADED_IMAGES_DEST'] = 'temp/'
images = UploadSet('images', IMAGES)
configure_uploads(app, images)

IsMainTain = True

#if (current_user.role >= role):

#def GetNumOfSunday():
#    today = datetime.date.today()
#    other_day = datetime.date(today.year,1,1)
#    result = today - other_day
#    days = result.days
#    sundays = int(days / 7) + ((other_day.weekday() + 1) + days % 7 >= 7)
#    print(days)
#    print(sundays)
#    print(days - sundays)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    #email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.Integer, default = 1)

class Gallery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial = db.Column(db.Integer, unique=True, default=0)
    image = db.Column(db.BLOB)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial = db.Column(db.Integer, unique=True, default=0)
    a1 = db.Column(db.Float, default = 1)
    a2 = db.Column(db.Float, default = 1)
    a3 = db.Column(db.Float, default = 1)
    a4 = db.Column(db.Float, default = 1)
    a5 = db.Column(db.Float, default = 1)
    a6 = db.Column(db.Float, default = 1)
    a7 = db.Column(db.Float, default = 1)
    a8 = db.Column(db.Float, default = 1)
    a9 = db.Column(db.Float, default = 1)
    a10 = db.Column(db.Float, default = 1)
    a11 = db.Column(db.Float, default = 1)
    a12 = db.Column(db.Float, default = 1)
    a13 = db.Column(db.Float, default = 1)
    a14 = db.Column(db.Float, default = 1)
    a15 = db.Column(db.Float, default = 1)
    a16 = db.Column(db.Float, default = 1)
    a17 = db.Column(db.Float, default = 1)
    a18 = db.Column(db.Float, default = 1)
    a19 = db.Column(db.Float, default = 1)
    a20 = db.Column(db.Float, default = 1)
    a21 = db.Column(db.Float, default = 1)
    a22 = db.Column(db.Float, default = 1)
    a23 = db.Column(db.Float, default = 1)
    a24 = db.Column(db.Float, default = 1)
    a25 = db.Column(db.Float, default = 1)
    a26 = db.Column(db.Float, default = 1)
    a27 = db.Column(db.Float, default = 1)
    a28 = db.Column(db.Float, default = 1)
    a29 = db.Column(db.Float, default = 1)
    a30 = db.Column(db.Float, default = 1)
    a31 = db.Column(db.Float, default = 1)
    a32 = db.Column(db.Float, default = 1)
    a33 = db.Column(db.Float, default = 1)
    a34 = db.Column(db.Float, default = 1)
    a35 = db.Column(db.Float, default = 1)
    a36 = db.Column(db.Float, default = 1)
    a37 = db.Column(db.Float, default = 1)
    a38 = db.Column(db.Float, default = 1)
    a39 = db.Column(db.Float, default = 1)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('帳號', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('密碼', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('記住我')

#class RegisterForm(FlaskForm):
#    #email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
#    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
#    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class ResetPasswordForm(FlaskForm):
    oldPass = PasswordField('舊密碼', validators=[InputRequired(), Length(min=8, max=80)])
    newPass = PasswordField('新密碼', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='新密碼與確認密碼不符')])
    confirm = PasswordField('確認密碼', validators=[InputRequired()])

class A539Form(FlaskForm):
    serial = IntegerField('期數', validators=[InputRequired(), NumberRange(min=100000000, max=999999999)])
    a1 = FloatField('1', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a2 = FloatField('2', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a3 = FloatField('3', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a4 = FloatField('4', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a5 = FloatField('5', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a6 = FloatField('6', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a7 = FloatField('7', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a8 = FloatField('8', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a9 = FloatField('9', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a10 = FloatField('10', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a11 = FloatField('11', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a12 = FloatField('12', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a13 = FloatField('13', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a14 = FloatField('14', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a15 = FloatField('15', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a16 = FloatField('16', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a17 = FloatField('17', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a18 = FloatField('18', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a19 = FloatField('19', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a20 = FloatField('20', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a21 = FloatField('21', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a22 = FloatField('22', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a23 = FloatField('23', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a24 = FloatField('24', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a25 = FloatField('25', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a26 = FloatField('26', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a27 = FloatField('27', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a28 = FloatField('28', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a29 = FloatField('29', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a30 = FloatField('30', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a31 = FloatField('31', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a32 = FloatField('32', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a33 = FloatField('33', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a34 = FloatField('34', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a35 = FloatField('35', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a36 = FloatField('36', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a37 = FloatField('37', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a38 = FloatField('38', validators=[InputRequired(), NumberRange(min=0, max=100)])
    a39 = FloatField('39', validators=[InputRequired(), NumberRange(min=0, max=100)])

class AddGalleryForm(FlaskForm):
    serial = IntegerField('期數', validators=[InputRequired(), NumberRange(min=100000000, max=999999999)])
    image = FileField('圖片', validators=[FileAllowed(images, u'Image only!'), FileRequired(u'File was empty!')])
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/price')
def price():
    return render_template('price.html')

@app.route('/gallery')
def gallery():
    gallerys = Gallery.query.order_by(Gallery.id.desc()).limit(9).all()
    return render_template('gallery.html', gallerys=gallerys)

@app.route('/term')
def term():
    return render_template('term.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return render_template('login.html', form=form, msg="帳號或密碼錯誤")
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form, msg="")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password, role=1)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('dashboard'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user:
        PCF = check_password_hash(current_user.password, '12345678')
        return render_template('dashboard.html', PCF=PCF)
    return redirect(url_for('index'))

################################################################modify
@app.route('/user/modify', methods=['GET', 'POST'])
@login_required
def modify():
    form = ResetPasswordForm()
    return render_template('modify.html', form=form)

@app.route('/user/modifyC', methods=['GET', 'POST'])
@login_required
def modifyC():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.oldPass.data, method='sha256')
        if check_password_hash(current_user.password, form.oldPass.data):
            hashed_password = generate_password_hash(form.newPass.data, method='sha256')
            current_user.password = hashed_password
            db.session.commit()
            logout_user()
            return jsonify({'ok': True, 'reason': '修改成功'})
        return jsonify({'ok': False, 'reason': '密碼錯誤!'})
    return jsonify({'ok': False, 'reason': form.errors})

@app.route('/function/539Table', methods=['GET', 'POST'])
@login_required
def a539Table():
    global IsMainTain
    if not IsMainTain:
        record = Record.query.order_by(Record.id.desc()).first()
        d = {
            1 : record.a1,
            2 : record.a2,
            3 : record.a3,
            4 : record.a4,
            5 : record.a5,
            6 : record.a6,
            7 : record.a7,
            8 : record.a8,
            9 : record.a9,
            10 : record.a10,
            11 : record.a11,
            12 : record.a12,
            13 : record.a13,
            14 : record.a14,
            15 : record.a15,
            16 : record.a16,
            17 : record.a17,
            18 : record.a18,
            19 : record.a19,
            20 : record.a20,
            21 : record.a21,
            22 : record.a22,
            23 : record.a23,
            24 : record.a24,
            25 : record.a25,
            26 : record.a26,
            27 : record.a27,
            28 : record.a28,
            29 : record.a29,
            30 : record.a30,
            31 : record.a31,
            32 : record.a32,
            33 : record.a33,
            34 : record.a34,
            35 : record.a35,
            36 : record.a36,
            37 : record.a37,
            38 : record.a38,
            39 : record.a39,
            }
        d = sorted(d.items(), key=lambda x:x[1], reverse=True)
        return render_template('539Table.html', res=d, serial=record.serial)
    return '<h1>系統更新中!</h1>'
    
###############################################539fun pei###############################################

@app.route('/manager/539TableCheck', methods=['GET', 'POST'])
@login_required
def a539TableCheck():
    if current_user.role == 999999:
        data = request.get_json()
        checked = data.get('checked')
        global IsMainTain
        if isinstance(checked, bool):
            IsMainTain = checked
            return jsonify({'ok': True, 'reason': IsMainTain})
        return jsonify({'ok': False, 'reason': '型態錯誤'})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})

@app.route('/manager/539TableC', methods=['GET', 'POST'])
@login_required
def a539TableC():
    global IsMainTain
    if current_user.role == 999999:
        form = A539Form()
        m=""
        if IsMainTain:
            m="checked"
        return render_template('539TableC.html', form=form, IsMainTain=m)
    return '<h1>你沒有權限!</h1>'

@app.route('/manager/539TableCC', methods=['GET', 'POST'])
@login_required
def a539TableCC():
    if current_user.role == 999999:
        form = A539Form()
        if form.validate_on_submit():
            new_record = Record(
                serial = form.serial.data,
                a1=form.a1.data,
                a2=form.a2.data,
                a3=form.a3.data,
                a4=form.a4.data,
                a5=form.a5.data,
                a6=form.a6.data,
                a7=form.a7.data,
                a8=form.a8.data,
                a9=form.a9.data,
                a10=form.a10.data,
                a11=form.a11.data,
                a12=form.a12.data,
                a13=form.a13.data,
                a14=form.a14.data,
                a15=form.a15.data,
                a16=form.a16.data,
                a17=form.a17.data,
                a18=form.a18.data,
                a19=form.a19.data,
                a20=form.a20.data,
                a21=form.a21.data,
                a22=form.a22.data,
                a23=form.a23.data,
                a24=form.a24.data,
                a25=form.a25.data,
                a26=form.a26.data,
                a27=form.a27.data,
                a28=form.a28.data,
                a29=form.a29.data,
                a30=form.a30.data,
                a31=form.a31.data,
                a32=form.a32.data,
                a33=form.a33.data,
                a34=form.a34.data,
                a35=form.a35.data,
                a36=form.a36.data,
                a37=form.a37.data,
                a38=form.a38.data,
                a39=form.a39.data
			)
            db.session.add(new_record)
            db.session.commit()
            return jsonify({'ok': True, 'reason': '新增成功'})
        return jsonify({'ok': False, 'reason': form.errors})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})

###############################################會員管理#################################################################################

@app.route('/manager/usermanager', methods=['GET', 'POST'])
@login_required
def usermanager():
    if current_user.role == 999999:
        users = User.query.filter(User.role < current_user.role)
        return render_template('usermanager.html', users=users)
    return '<h1>你沒有權限!</h1>'

@app.route('/manager/DelUser', methods=['POST'])
@login_required
def DelUser():
    if current_user.role == 999999:
        data = request.get_json()
        user = User.query.filter_by(id=data.get('id')).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'ok': True, 'reason': user.username+'刪除成功'})
        else:
            return jsonify({'ok': False, 'reason': '查無此人!'})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})

@app.route('/manager/AddUser', methods=['POST'])
@login_required
def AddUser():
    if current_user.role == 999999:
        data = request.get_json()
        username = data.get('username')
        strLen = len(username)
        if strLen < 4 or strLen > 80:
            return jsonify({'ok': False, 'reason': '長度錯誤!'})
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({'ok': False, 'reason': '重複使用者'})
        hashed_password = generate_password_hash("12345678", method='sha256')
        new_user = User(username=username, password=hashed_password, role=1)
        if new_user:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'ok': True, 'reason':  new_user.username+'新增成功'})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})

@app.route('/manager/ResetUser', methods=['POST'])
@login_required
def ResetUser():
    if current_user.role == 999999:
        data = request.get_json()
        user = User.query.filter_by(id=data.get('id')).first()
        if user:
            user.password = generate_password_hash("12345678", method='sha256')
            db.session.commit()
            return jsonify({'ok': True, 'reason':  user.username+'重置成功'})
        else:
            return jsonify({'ok': False, 'reason': '查無此人!'})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})

###############################################會員管理#################################################################################
@app.route('/GalleryImage/<id>/<w>/<h>')
def GalleryImage(id, w, h):
    gallery = Gallery.query.filter_by(id=id).first()
    img = cv2.imdecode(numpy.fromstring(gallery.image, numpy.uint8), cv2.IMREAD_UNCHANGED)
    if w.isdigit() and h.isdigit():
        img = cv2.resize(img, (int(w), int(h)))
    ret, png = cv2.imencode('.png', img)
    return png.tobytes()

@app.route('/manager/Gallerymanager', methods=['GET', 'POST'])
@login_required
def Gallerymanager():
    if current_user.role == 999999:
        gallerys = Gallery.query.order_by(Gallery.id.desc()).limit(9).all()
        form = AddGalleryForm()
        return render_template('Gallerymanager.html', gallerys=gallerys, form=form)
    return '<h1>你沒有權限!</h1>'

#AddGallery
@app.route('/manager/AddGallery', methods=['POST'])
@login_required
def AddGallery():
    if current_user.role == 999999:
        form = AddGalleryForm()
        if form.validate_on_submit():
            newGallery = Gallery(
                serial = form.serial.data,
                #image = base64.b64encode(form.image.data.read())
                image = form.image.data.read()
            )
            db.session.add(newGallery)
            db.session.commit()
            return jsonify({'ok': True, 'reason': str(newGallery.serial)+'期新增成功'})
        return jsonify({'ok': False, 'reason': form.errors})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})
    
#DelGallery
@app.route('/manager/DelGallery', methods=['POST'])
@login_required
def DelGallery():
    if current_user.role == 999999:
        data = request.get_json()
        gallery = Gallery.query.filter_by(id=data.get('id')).first()
        if gallery:
            db.session.delete(gallery)
            db.session.commit()
            return jsonify({'ok': True, 'reason': '第' + str(gallery.serial) + '期刪除成功'})
        else:
            return jsonify({'ok': False, 'reason': '查無此紀錄!'})
    return jsonify({'ok': False, 'reason': '你沒有權限!'})
###############################################會員紀錄管理#############################################################################


if __name__ == '__main__':
    app.run(host= '0.0.0.0', port=5000, debug=False)
