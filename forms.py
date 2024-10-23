from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email
from flask_pagedown.fields import PageDownField

class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField("About_me")
    submit = SubmitField('Submit')



class PostForm(FlaskForm):
    body = TextAreaField('Share your thoughts here', validators=[DataRequired()])
    submit = SubmitField('Submit')


class EditPostFrom(FlaskForm):
    body = TextAreaField('Edit your post here', validators=[DataRequired()])
    submit = SubmitField('Confirm')


    
