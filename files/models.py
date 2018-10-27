from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from files.__init__ import db, login_manager, app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


class rec(db.Model):
    extend_existing = True
    id = db.Column(db.Integer, primary_key=True)
    rec_name = db.Column('rec_name', db.String(100), nullable=False)
    prep_time = db.Column('prep_time', db.String(50), default="")
    cook_time = db.Column('cook_time', db.String(50), default="")
    rec_description = db.Column('rec_description', db.Text, nullable=False)
    rec_instruction = db.Column('rec_instruction', db.Text, nullable=False)
    ing_1 = db.Column('ing_1', db.String(50), nullable=False)
    ing_2 = db.Column('ing_2', db.String(50), default="")
    ing_3 = db.Column('ing_3', db.String(50), default="")
    ing_4 = db.Column('ing_4', db.String(50), default="")
    ing_5 = db.Column('ing_5', db.String(50), default="")
    ing_6 = db.Column('ing_6', db.String(50), default="")
    ing_7 = db.Column('ing_7', db.String(50), default="")
    ing_8 = db.Column('ing_8', db.String(50), default="")
    ing_9 = db.Column('ing_9', db.String(50), default="")
    ing_10 = db.Column('ing_10', db.String(50), default="")
    minPrice = db.Column('minPrice', db.Integer)
    maxPrice = db.Column('maxprice', db.Integer)
    calories = db.Column('calories', db.Integer)
    fat = db.Column('fat', db.String(10), default="")
    cholesterol = db.Column('cholesterol', db.String(10), default="")
    sodium = db.Column('sodium', db.String(10), default="")
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return 'rec({self.rec_name}, {self.prep_time}, {self.cook_time}, {self.rec_instruction}, {self.rec_description}, {self.fat}, {self.cholesterol}, {self.sodium}, {self.calories})'


class postss(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=True)
    link_current = db.Column(db.String(1000), nullable=True)
    content_current = db.Column(db.String(1000), nullable=True)
    post_type = db.Column(db.String(50), nullable=False)
    post_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"postss('{self.content}','{self.post_date}', '{self.post_type}', '{self.user_id}')"

class favs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    recipe_id = db.Column(db.Integer, nullable=False)


class users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Unicode, unique=True, nullable=False)
    email = db.Column(db.Unicode, unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profilePic = db.Column(db.String(40), default="emptyProf.png")
    firstName = db.Column(db.String(20), default="")
    lastName = db.Column(db.String(20), default="")
    displayName = db.Column(db.String(20), default="")
    cookingExperience = db.Column(db.String(12), default="Beginner")
    country = db.Column(db.String(30), default="")
    # posts= db.relationship('posts', backref='users', lazy=True)

    # CREATING TOKEN FOR PASSWORD RESET

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    # METHOD FOR TOKEN VERIFICATION

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return users.query.get(user_id)

    def __repr__(self):
        return "users('{self.username}', {self.email}', {self.password}', {self.profilePic}', {self.firstName}', {self.lastName}', {self.displayName}',{self.cookingExperience}',{self.country}')"
