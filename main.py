import os
from functools import wraps
from flask import Flask, render_template, make_response, session, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, logout_user, login_user, current_user, AnonymousUserMixin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
import random
from datetime import datetime 
from flask_moment import Moment
from forms import EditProfileForm, PostForm, EditPostFrom
import oauthlib


import hashlib
from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from flask_pagedown import PageDown
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)

app.config['SECRET_KEY'] = 'I like monkeys'
app.config['FLASKY_POST_PER_PAGE'] = 3

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = \
'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

google_bp = make_google_blueprint(
    client_id='487227781491-1umj173li4t601pc87g5gehs1cf4a06a.apps.googleusercontent.com',
    client_secret='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',
    redirect_to='google_login',
    scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", 'openid'],
    offline=False
)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
app.register_blueprint(google_bp, url_prefix='/google_login')
# Конфігурація імейла 

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'janbel7991@gmail.com'
app.config['MAIL_PASSWORD'] = 'fsof opaq aubm fjpz'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

moment = Moment(app)
app.config['FLASKY_ADMIN'] = 'janbel7991@gmail.com'
pagidown = PageDown(app)

class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now) 


def send_email(message):
    mail.send(message)
    return 'Mail sent successfully'

class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                return 'You have not acces to this page'
            return f(*args, **kwargs)
        return decorated_function
    return decorator
    
def admin_required(f):
    return permission_required(Permission.ADMIN)(f)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text)
    member_since = db.Column(db.DateTime(), default=datetime.now)
    last_seen = db.Column(db.DateTime(), default=datetime.now)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    avatar_hash = db.Column(db.String(32))


    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id], backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic', cascade='all, delete-orphan')
    
    follower = db.relationship('Follow', foreign_keys=[Follow.followed_id], backref=db.backref('followed', lazy='joined'),
                               lazy='dynamic', cascade='all, delete-orphan')
    
    posts = db.relationship('Post', backref='author', lazy='dynamic')



    comments = db.relationship('Comment', backref='user', lazy='dynamic')

    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))


    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id==Post.author_id).filter(Follow.follower_id==self.id)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        # Використовуємо легший метод хешування
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __init__(self, **kwargs) -> None:
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Admin').first()
                if self.role is None:
                    self.role = Role.query.filter_by(default=True)

        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)  # Виправлення логіки
            db.session.add(f)
            db.session.commit()  # Не забудь коміт для збереження змін

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)
            db.session.commit()  # Не забудь коміт для збереження змін

    def is_following(self, user):
        if user is None or user.id is None:  # Додай перевірку на None
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed(self, user):
        if user is None or user.id is None:  # Додай перевірку на None
            return False
        return self.followers.filter_by(follower_id=user.id).first() is not None
                    
    def ping(self):
        self.last_seen = datetime.now()
        db.session.add(self)
        db.session.commit()
    
    def can(self, perm):
        return self.role is not None and self.role.has_permissions(perm)

    def is_admin(self):
        return self.can(Permission.ADMIN)
    
    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return f'{url}/{hash}?s={size}&d={default}&r={rating}'

    def __repr__(self):
        return '<Role %r>' % self.name

def users(count=100):
    fake = Faker()
    i = 0
    while i < count:
        email = fake.email()
        if User.query.filter_by(email=email).first() is not None:
            continue  # Пропустити, якщо такий email вже є
        u = User(email=email,
                 password='password',
                 confirmed=True,
                 name=fake.name(),
                 location=fake.city(),
                 about_me=fake.text(),
                 member_since=fake.past_date())
        db.session.add(u)
        try:
            db.session.commit()
            i += 1
        except IntegrityError:
            db.session.rollback()


def posts(count=100):
    fake = Faker()
    user_count = User.query.count()
    for i in range(count):
        u = User.query.offset(randint(0, user_count - 1)).first()
        p = Post(body=fake.text(),
                 timestamp=fake.past_date(),
                 author=u)
        db.session.add(p)
    db.session.commit()


    
class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
    
    def is_admin(self):
        return False
    

    

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.now)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


    
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)

    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs) -> None:
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def add_permission(self, perm):
        if not self.has_permissions(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permissions(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permissions(self, perm):
        return self.permissions & perm == perm

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.WRITE, Permission.FOLLOW],

            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE, Permission.MODERATE],

            'Admin': [Permission.FOLLOW, Permission.COMMENT,
                      Permission.WRITE, Permission.MODERATE, 
                      Permission.ADMIN]
        }
        default_role = 'User'

    
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
                db.session.add(role)  # Додаємо нову роль до сесії
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)

        db.session.commit()  # Зберігаємо всі зміни в базі даних

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(505)
def unknown_exception(e):
    return render_template('505.html'), 505

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# @main.app_context_processor
# def inject_permissions():
#     return dict(Permission=Permission)

# @app.before_request
# def before_request():
#     if current_user.is_authenticated:
#         current_user.ping()


@app.route('/', methods=['GET', 'POST'])
def main():
    
    

    return render_template('home.html')

@app.route('/create-comment', methods=['GET', 'POST'])
def create_comment():
    if request.method == 'POST':
        body = request.form.get('comment_body')
        
        new_comment = Comment(body=body, user_id=current_user.id)
        db.session.add(new_comment)
        db.session.commit()
        theme = 'Comment in proccesing'
        body = f" your comment: {new_comment.body} will appear soon"
        msg = Message(subject=theme, sender=app.config['MAIL_USERNAME'], recipients=[current_user.email])
        msg.body = body
        send_email(msg)

    return render_template('comment.html')
        


@app.route('/response')
def response():
    response = make_response('<h1> This document carries cookie <h1>')
    response.set_cookie('answer', '42')
    return response


@app.route('/secretpage')
@login_required
def secret_page():
    return 'This is secrec page'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = User.query.all()

        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')
        user = User.query.filter_by(email=email).first()
        
        if user and user.verify_password(password):
            login_user(user, remember_me)
            print('you logged in sucsesfully')
            return redirect(url_for('main'))
        else:
            return 'Email or password is incorrect'
            redirect(url_for('sign_up'))

    else:
        print('something gone wrong')
    return render_template('login.html')
@app.route('/logout')
@login_required
def logout():
    
    flash('You have been logged out')
    logout_user()
    return redirect(url_for('main'))


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')


        # Перевірка на існування ім'я та імейл в базі данних
        
        user_email = User.query.filter_by(email=email).first()
        
        
        
        if user_email:
            flash('This email is already registered.')
            return redirect(url_for('sign_up'))
        
        if password == password_confirm:
            hashed_password = generate_password_hash(password=password)
            new_user = User(name=username, email=email, password=hashed_password)
            new_user.password = password
            db.session.add(new_user)
            db.session.commit()
            
            
            flash('Registration succesfull!, please log in')
            return redirect(url_for('login'))
        else:
            flash('passwords do not match')
            return redirect(url_for('sign_up'))

    return render_template('sign_up.html')



@app.route('/confirm_email', methods=['GET', 'POST'])
@login_required
def confirm_email():
    if request.method == 'GET':
        # Генерація та збереження коду підтвердження в сесії
        confirm_number = random.randrange(1, 101)
        session['confirm_number'] = str(confirm_number)

        # Відправка листа
        theme = 'Account confirmation'
        body = str(confirm_number)
        msg = Message(subject=theme, sender=app.config['MAIL_USERNAME'], recipients=[current_user.email])
        msg.body = body
        mail.send(msg)
    
    if request.method == 'POST':
        user_confirm_number = request.form.get('confirm_email')
        if user_confirm_number == session.get('confirm_number'):
            current_user.confirmed = True
            db.session.commit()  # Збереження змін в базу даних
            return 'You confirmed your account successfully'
        else:
            flash('Incorrect confirmation number. Please try again.')

    return render_template('confirm_email.html')


@app.route('/admin')
@login_required
@admin_required
def admin():
    return 'This page is only for admin'


@app.route('/user/<username>')
def user(username):
    user = User.query.filter_by(name=username).first_or_404()
    posts = user.posts.order_by(Post.timestamp.desc()).all()

    timestamp = str(user.member_since)
    timestamp2 = str(user.last_seen)
    dt_object = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
    dt_object2 = datetime.strptime(timestamp2, '%Y-%m-%d %H:%M:%S.%f')
    formatted_timestamp = dt_object.strftime('%Y-%m-%d %H:%M:%S')
    formatted_timestamp2 = dt_object2.strftime('%Y-%m-%d %H:%M:%S')

    # рахунок підписок та підписників (я вигадав)
    user_followers = user.follower.all()
    user_followed = user.followed.all()

    followers = 0
    followed = 0

    for u in user_followers:
        followers += 1

    for u in user_followed:
        followed += 1

    return render_template('user.html', user=user, formatted_timestamp=formatted_timestamp, formatted_timestamp2=formatted_timestamp2,
                           posts=posts, followers=str(followers), followed=str(followed))

@app.route('/user/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user_profile(id):
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user._get_current_object())
        db.session.commit()
        flash('Your profile has been updated.')
        return redirect(url_for('user', username=current_user.name))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)

@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    page = request.args.get('page', 1, type=int)
    
    # Отримуємо значення cookie для визначення, що показувати (всі пости або пости від підписників)
    show_followed = request.cookies.get('show_followed', '')

    if show_followed:
        # Якщо cookie встановлено (тобто користувач вибрав перегляд постів від підписників)
        # Зв'язування таблиць між собою з допомогою метода join
        pagination = Post.query.join(Follow, Follow.followed_id == Post.author_id)\
            .filter(Follow.follower_id == current_user.id)\
            .order_by(Post.timestamp.desc())\
            .paginate(page=page, per_page=3, error_out=False)
    else:
        # Якщо cookie немає або користувач вибрав перегляд усіх постів
        pagination = Post.query.order_by(Post.timestamp.desc()).paginate(
            page=page, per_page=3, error_out=False
        )

    # Отримуємо пости для поточної сторінки
    posts = pagination.items
    
    return render_template('posts.html', posts=posts, pagination=pagination)

@app.route('/write-post', methods=['GET', 'POST'])
@login_required
def write_post():
    form = PostForm()
    
    if form.validate_on_submit():
        post = Post(body=form.body.data,
                    author=current_user._get_current_object())
        
        db.session.add(post)
        db.session.commit()

        return redirect(url_for('.write_post'))
    
    return render_template('write_post.html', form=form)

@app.route('/post/<int:id>')
def post(id):
    post = Post.query.get_or_404(id)
    return render_template('one_post.html', posts=[post])

@app.route('/edit_post/<int:id>', methods=['GET', 'POST'])
def edit_post(id):
    post = Post.query.get_or_404(id)
    form = EditPostFrom()
   
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.commit()
        return redirect(url_for('post', id=post.id))
    
    form.body.data = post.body

    return render_template('edit_post.html', form=form)



@app.route('/google_login')
def google_login():

    if not google.authorized:
        return redirect(url_for('google.login'))
    
    try:
        # Отримуємо інформацію про користувача
        resp = google.get('/oauth2/v1/userinfo')
        assert resp.ok, resp.text  # Перевірка на помилку

        email = resp.json()['email']
        name = resp.json()['name']

        # Перевіряємо, чи користувач уже є в базі даних
        user = User.query.filter_by(email=email).first()

        if not user:
            new_user = User(name=name, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
        else:
            login_user(user)
            flash('You logged in successfully')

        return redirect(url_for('main'))

    except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
        # Якщо токен закінчився, перенаправляємо користувача на логін або оновлюємо токен
        
        return redirect(url_for('google.login'))

@app.route('/follow/<username>')
@login_required

def follow(username):
    user = User.query.filter_by(name=username).first()
    if user is None:
        print('Invalid user.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        print('You are already following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    
    print('You are now following %s.' % username)
    return redirect(url_for('.user', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(name=username).first()
    print(current_user.is_following(user))
    # Перевіряємо, чи знайдено користувача
    if user is None:
        print('User %s not found.' % username)
        return redirect(url_for('index'))

    # Перевіряємо, чи користувач не намагається відписатися сам від себе
    if user == current_user:
        print('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))

    try:
        current_user.unfollow(user)
          # Не забудь коміт для збереження змін
        print('You have unfollowed %s.' % username)
    except Exception as e:
        db.session.rollback()  # Якщо щось пішло не так, скасувати зміни
        print('Something went wrong: %s' % str(e))
    
    return redirect(url_for('user', username=username))


@app.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(name=username).first_or_404()

    # Отримуємо номер сторінки з URL
    page = request.args.get('page', 1, type=int)

    # Використовуємо paginate для розбиття на сторінки
    pagination = user.follower.paginate(page=page, per_page=10, error_out=False)

    # Отримуємо список підписників для поточної сторінки
    followers = [{'follower': follow.follower, 'timestamp': follow.timestamp} for follow in pagination.items]

    return render_template('followers.html', user=user, followers=followers, pagination=pagination)


@app.route('/followed/<username>')
def followed(username):
    user = User.query.filter_by(name=username).first_or_404()

    # Отримуємо номер сторінки з URL
    page = request.args.get('page', 1, type=int)

    # Використовуємо paginate для розбиття на сторінки
    pagination = user.followed.paginate(page=page, per_page=10, error_out=False)

    # Отримуємо список тих, на кого користувач підписаний
    followed_users = [{'followed': follow.followed, 'timestamp': follow.timestamp} for follow in pagination.items]

    return render_template('followed.html', user=user, followed_users=followed_users, pagination=pagination)


@login_required 
@app.route('/all')
def show_all():
    resp = make_response(redirect(url_for('posts')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60) # 30 days
    return resp

@login_required 
@app.route('/followed') 
def show_followed():
    resp = make_response(redirect(url_for('posts')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60) # 30 days
    return resp

