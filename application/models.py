from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.JSON)
    jwt_token = db.Column(db.String(500))

class Favorite(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    item_name = db.Column(db.String, primary_key=True)
    user = db.relationship('User', backref='favorites')
