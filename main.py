from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship 
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUserForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import functools
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('app_secret_key')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##SETUP LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

##SETUP GRAVATAR
gravatar = Gravatar(app,
    size=100,
    rating='g',
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="blog_post")
    # db.create_all()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    text = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    blog_post = relationship("BlogPost", back_populates="comments")

## DECORATORS
def admin_only(func):
    @functools.wraps(func)
    def wrapper_for_keiths_decorator(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return wrapper_for_keiths_decorator


## ROUTES

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

@app.route('/register', methods=["GET", "POST"])
def register():
    user_form = CreateUserForm()
    if user_form.validate_on_submit():
        # make sure user doesn't already exist
        existing_user = User.query.filter_by(email=request.form.get('email')).first()
        if existing_user:
            flash("There is already a user account with that email address. Log in instead.")
            return redirect(url_for('login'))
        
        user = User()
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        hashed_password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha1', salt_length=8)
        user.password = hashed_password
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("successfully added user")
        return redirect(url_for('get_all_posts'))
    else:
        return render_template("register.html", form=user_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        # check if email exists
        existing_user = User.query.filter_by(email=request.form.get('email')).first()
        if existing_user is None:
            flash("There is no user with that email. Try again.")
            return redirect(url_for('login'))
        else:
            # check if password is correct
            if check_password_hash(existing_user.password, request.form.get('password')) == False:
                flash("Incorrect password. Try again.")
                return redirect(url_for('login'))
            else:
                login_user(existing_user)
                return redirect(url_for('get_all_posts'))
    else:
        return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comments_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comments_form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(text=request.form['comment'],
                    post_id=post_id,
                    user_id=current_user.id)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            flash("You must be logged in to leave a comment.")
            return redirect(url_for('login'))
    else:
        return render_template("post.html", post=requested_post, form=comments_form, comments=requested_post.comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        print(f"author = {current_user.id}")
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)
