from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, IntegerField, HiddenField
from wtforms.fields.html5 import DecimalRangeField
from wtforms.validators import InputRequired, Email, Length, EqualTo, DataRequired, ValidationError, Optional, NumberRange
from files.__init__ import users, rec, postss


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = users.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = users.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')


class RecipeForm(FlaskForm):
    rec_description = TextAreaField('Description')
    rec_name = StringField('Recipe Name', validators=[DataRequired()])
    prep_time = StringField('Preperation Time', validators=[DataRequired()])
    cook_time = StringField('Cook Time', validators=[DataRequired()])
    rec_instruction = TextAreaField('Instruction')
    ings = HiddenField()
    tags = HiddenField()
    calories = StringField('Calories')
    fat = StringField('Fat')
    cholesterol = StringField('Cholesterol')
    sodium = StringField('Sodium')
    minPrice = IntegerField('Min Price', validators = [DataRequired(), NumberRange(min=0, message = "Enter a valid minimum price")])
    maxPrice = IntegerField('Max Price', validators = [DataRequired(), NumberRange(min=0, message = "Enter a valid maximum price")])
    recipePic = FileField('Upload Recipe Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Post')

    def validate_price(self, minPrice, maxPrice):
        if minPrice < 0:
            raise ValidationError('Minimum Price must be above 0')
        if maxPrice > 9999:
            raise ValidationError('Maximum Price must be above 9999')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = users.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[Optional(), Length(min=2, max=20)])
    email = StringField('Email', validators=[Optional(), Email()])
    firstname = StringField('First Name', validators=[Optional(), Length(min=2, max=20)])
    lastname = StringField('Last Name', validators=[Optional(), Length(min=2, max=20)])
    cooking_exp = SelectField(
        'Cooking Experience',
        choices=[('Novice', 'Novice'), ('Intermediate', 'Intermediate'), ('Expert', 'Expert')],
        validators=[Optional()]
    )
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = users.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = users.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

####################################### POSTING FORMS #############################################


class PostForm(FlaskForm):
    #title = StringField('Title', validators=[DataRequired()])
    contentNormal = TextAreaField('', validators=[DataRequired()])
    submitNormal = SubmitField('Post')


class PostFormHungryFor(FlaskForm):
    #title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('', validators=[DataRequired()])
    submit = SubmitField('Post')


class PostFormCurrentlyEating(FlaskForm):
    #title = StringField('Title', validators=[DataRequired()])
    linkCurrent = TextAreaField("")
    contentCurrent = TextAreaField("")
    submitCurrent = SubmitField('Post')


class RecipeSearchForm(FlaskForm):
    #title = StringField('Title', validators=[DataRequired()])
    keyWord = StringField('')
    submit = SubmitField('Search')


class PriceRangeForm(FlaskForm):
    rangef = DecimalRangeField('Price Range', default=0)


class CommentForm(FlaskForm):
    commentBox = TextAreaField("")
    submitComment = SubmitField("Post Comment")


class FindFriends(FlaskForm):
    friend = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField("Find Friend")
