import ConfigParser
import logging
import warnings

# to avoid the generation of .pyc files
import sys

sys.dont_write_bytecode = True

# necessary import to ignore any ExtdepricationWarning warnings for external
# libraries

from flask.exthook import ExtDeprecationWarning
warnings.simplefilter('ignore', ExtDeprecationWarning)

# other essential imports

from logging.handlers import RotatingFileHandler
from flask import (Flask, url_for, g, render_template, flash, redirect, abort)
from flask.ext.bcrypt import check_password_hash
from flask.ext.login import (LoginManager, login_user, logout_user,
                             login_required, current_user)
import models
import forms

app = Flask(__name__)
app.secret_key = 'sefdewfewr43r535rewfwda!'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(userid):
  try:
    return models.User.get(models.User.id == userid)
  except models.DoesNotExist:
    return None

# to connect to the database before each request

@app.before_request
def before_request():
  g.db = models.DATABASE
  g.db.get_conn()
  g.user = current_user


# to close the database connection after each request

@app.after_request
def after_request(response):
  g.db.close()
  return response


# routing to my landing page which is the portfolio section

@app.route("/myprofile/<username>")
@app.route("/myprofile")
@login_required
def profile(username=None):
  template='portfolio.html'
  try:
    if username and username != current_user.username:
       user = models.User.select().where(models.User.username**username).get()
       this_route = url_for('.profile')
       app.logger.info( current_user.username + " viewed " + username + "'s personal Profile page " + this_route)
    else:
       user=current_user
       this_route = url_for('.profile')
       app.logger.info( current_user.username  + " viewed his/her personal Profile page " + this_route)
    if username:
       template = 'portfolio.html'
  except models.DoesNotExist:
      abort(404)
  else:    
      return render_template(template, user=user)  


# routing to the about section

@app.route("/about/<username>")
@app.route("/about")
@login_required
def about(username=None):
  template='about.html'
  try:
     if username and username != current_user.username:
       user = models.User.select().where(models.User.username**username).get()
       this_route = url_for('.about')
       app.logger.info( current_user.username + " viewed " + username + "'s personal About page " + this_route)
     else:
       user=current_user
       this_route = url_for('.about')
       app.logger.info( current_user.username  + " viewed his/her personal About Me page " + this_route)
     if username:
       template = 'about.html'
  except models.DoesNotExist:
      abort(404)
  else:
      return render_template(template, user=user)  


# routing to the create a new post section

@app.route("/new_post", methods=('GET','POST'))
@login_required
def post(username=None):
  if username and username != current_user.username:
    user = models.User.select().where(models.User.username**username).get()
    this_route = url_for('.post')
    app.logger.info( current_user.username + " created a new post on " +
    username + "'s post feed section " + this_route)
  else:
    user=current_user
    this_route = url_for('.post')
    app.logger.info( current_user.username + " created a new post on his/her post feed section "
    + this_route)
  form = forms.PostForm()
  if form.validate_on_submit():
    models.Post.create(user=g.user._get_current_object(),
                      content=form.content.data.strip())
    flash("Message posted!", "success")
    return redirect(url_for('root'))
  return render_template('post.html', form=form, user=user)  


# the user is redirected to the root page after posting a new message and can
# view their recent posts on the post feed section

@app.route("/")
def root(username=None):
  if username and username != current_user.username:
    user = models.User.select().where(models.User.username**username).get()
  else:
    user = current_user
  this_route = url_for('.root')
  app.logger.info(current_user.username + " was redirected to the root page  " + this_route)
  stream = models.Post.select().limit(100)
  return render_template('stream.html',user=user, stream=stream)


# routing to the posts stream section

@app.route('/stream')
@app.route('/stream/<username>')
def stream(username=None):
  template='stream.html'
  if username and username != current_user.username:
    this_route = url_for('.stream')
    app.logger.info(current_user.username + " viewed " + username + "'s Stream section  " 
    + this_route)
    try:
       user = models.User.select().where(models.User.username**username).get()
    except models.DoesNotExist:
       abort(404)
    else:  
       stream=user.posts.limit(100)
  else:
    stream=current_user.get_stream().limit(100)
    user=current_user
    this_route = url_for('.stream')
    app.logger.info(current_user.username + " viewed his/her Stream section  " 
       + this_route)

  if username:
      template = 'user-stream.html'
  return render_template(template, stream=stream, user=user)    


# routing to each individual post

@app.route('/post/<int:post_id>')
def view_post(post_id, username=None):
  if username and username != current_user.username:
    user = models.User.select().where(models.User.username**username).get()
  else:
    user=current_user
  posts = models.Post.select().where(models.Post.id == post_id)
  if posts.count() == 0:
    abort(404)
  return render_template('stream.html', stream=posts, user=user)

# function that adds one follower in the relationship table for the selected user

@app.route('/follow/<username>')
@login_required
def follow(username):
  try:
      to_user = models.User.get(models.User.username**username)
  except models.DoesNotExist:
      abort(404)
  else:
       try:
           models.Relationship.create(
             from_user=g.user._get_current_object(),
             to_user=to_user
           )
       except models.IntegrityError:
           pass
       else:
           flash("You're now following {}!".format(to_user.username),"success")
           app.logger.info(current_user.username + " is now following " + username)
  return redirect(url_for('stream',username=to_user.username))    


# function that deletes the follower instance from the relationship table for
# the selected user

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
  try:
      to_user = models.User.get(models.User.username**username)
  except models.DoesNotExist:
      abort(404)
  else:
       try:
           models.Relationship.get(
             from_user=g.user._get_current_object(),
             to_user=to_user
           ).delete_instance()
       except models.IntegrityError:
           pass
       else:
           flash("You've unfollowed {}!".format(to_user.username),"success")
           app.logger.info(current_user.username + " is now unfollowing " +
           username)
  return redirect(url_for('stream',username=to_user.username))    

# routing to the register page
@app.route('/register', methods=('GET','POST'))
def register():
  this_route = url_for('.register')
  app.logger.info("Someone visited the Register page " + this_route)
  form = forms.RegisterForm()
  if form.validate_on_submit():
    flash("Congratulations, you have successfully registered!", "success")
    models.User.create_user(
      username=form.username.data,
      email=form.email.data,
      password=form.password.data
    )
    return redirect(url_for('profile'))
  return render_template('register.html', form=form) 


# routing to the login page

@app.route('/login', methods=('GET','POST'))  
def login():
  this_route = url_for('.login')
  app.logger.info("Someone visited the Login page " + this_route)
  form = forms.LoginForm()
  if form.validate_on_submit():
    try:
      user = models.User.get(models.User.email == form.email.data)
    except models.DoesNotExist:
      flash("Your email or password doesn't match!", "error")
    else:
      if check_password_hash(user.password, form.password.data):
        login_user(user)
        flash("You've been logged in!", "success")
        return redirect(url_for('profile'))
      else:
        flash("Your email or password doesn't match!", "error")
  return render_template('login.html', form=form)


# routing to the logout page which redirects the user to the login page

@app.route('/logout')
@login_required
def logout():
  this_route = url_for('.logout')
  app.logger.info( current_user.username + " requested to logout " + this_route)
  logout_user()
  flash("You've been logged out. Come back soon!","success")
  return redirect(url_for('login'))


# parsing configuration details from an external file

def init (app):
  config = ConfigParser.ConfigParser()
  try:
    config_location = "etc/defaults.cfg"
    config.read(config_location)

    app.config['DEBUG'] = config.get("config", "debug")
    app.config['ip_address'] = config.get("config", "ip_address")
    app.config['port'] = config.get("config", "port")
    app.config['url'] = config.get("config", "url")

    app.config['log_file'] = config.get("logging", "name")
    app.config['log_location'] = config.get("logging", "location")
    app.config['log_level'] = config.get("logging", "level")

  except:
    print "Could not read configuration file from: " , config_location


# setting up a logging feature to record action logs into a text file    

def logs(app):
  log_pathname = app.config['log_location']+ app.config['log_file']
  file_handler = RotatingFileHandler(log_pathname, maxBytes=1024*1024*10 ,
  backupCount=1024)
  file_handler.setLevel( app.config['log_level'])
  formatter = logging.Formatter("%(levelname)s | %(asctime)s | %(module)s | %(funcName)s | %(message)s")
  file_handler.setFormatter(formatter)
  app.logger.setLevel(app.config['log_level'])
  app.logger.addHandler(file_handler)


# error handling mechanism to catch all the 404 errors and to redirect the user to
# a custom 404 page

@app.errorhandler(404)
def not_found(error):
  return render_template('404.html'), 404


# initialisation function

if __name__ == "__main__":
  init(app)
  logs(app)
  models.initialize()
  try:
  # first user created to populate the user table
    models.User.create_user(
       username='poisonphoebe',
       email='poisonphoebe@hotmail.com',
       password='password',
       admin=True
     )
  except ValueError:
    pass
  app.run(
    host = app.config['ip_address'],
    port = int(app.config['port']))
