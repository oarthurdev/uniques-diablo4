from flask import Flask
from .models import db
from .routes import bp as main_bp
from .config import Config
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    app.config.from_object('application.config.Config')
    db.init_app(app)
    app.register_blueprint(main_bp)
    CORS(app)
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
    return app
