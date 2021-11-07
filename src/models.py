from flaskweb import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(70), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    token = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    crypto_name = db.Column(db.String(20), nullable=False)
    header = db.Column(db.Text, nullable=False)
    paragraph = db.Column(db.Text, nullable=False)
    img = db.Column(db.Text)

    def __init__(self, crypto_name, header, paragraph, img):
        self.crypto_name = crypto_name
        self.header = header
        self.paragraph = paragraph
        self.img = img