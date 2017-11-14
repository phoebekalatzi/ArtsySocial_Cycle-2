# to avoid the generation of .pyc files
import sys

sys.dont_write_bytecode = True

from  flask_wtf import FlaskForm


from models import User
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import (DataRequired, Regexp, ValidationError, Email,
                               Length, EqualTo )

def name_exists(form, field):
  if User.select().where(User.username == field.data).exists():
    raise ValidationError('User with that name already exists.')

def email_exists(form, field):
  if User.select().where(User.email == field.data).exists():
    raise ValidationError('User with that email already exists.')

# custom validator to enforce secure passwords
def password_check(form, field):

   if(len(field.data)< 10 or len(field.data) > 128):
     raise ValidationError('Password must be longer than 10 characters.')

   if ((not any(x.isupper() for x in field.data)) or (not any(x.islower() for x in field.data))
    or (not any(x.isdigit() for x in field.data))):
       raise ValidationError('Your password needs at least 1 uppercase letter, 1 lowercase letter and 1 digit')


class RegisterForm(FlaskForm):
   username = StringField(
     'Username...',
      validators=[
        DataRequired(),
        Regexp(
          r'^[a-zA-Z0-9_]+$',
        message=("Username should be one word, letters, "
                "numbers, and underscores only.")
           ), 
        name_exists,
        Length(max=64, message="Your username must not exceed 64 characters")
    ])
   email = StringField(
      'Email...',
      validators=[
         DataRequired(),
         Email(),
         email_exists,
         Length(max=254, message="Your email address must not exceed 254 characters")
    ])
   password = PasswordField(
    'Password...',
     validators=[
       DataRequired(),
       password_check
    ])

   password2 = PasswordField(
      'Confirm Password...',
      validators=[DataRequired(),
      EqualTo('password', message='Passwords must match')]
 )   

class LoginForm(FlaskForm):
     email = StringField('Email...', validators=[DataRequired(), Email()])
     password = PasswordField('Password...', validators=[DataRequired()])

class PostForm(FlaskForm):
    content = TextAreaField("Post your message...", validators=[DataRequired()])
