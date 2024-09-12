from flask import Flask, session
from .models import db
from .routes import bp as main_bp
from .config import Config
from flask_cors import CORS
from flask_session import Session  # For server-side session management
import secrets

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)  # Use your config class

    # Initialize database
    db.init_app(app)

    # Initialize Flask-Session if using server-side sessions
    app.config['SESSION_TYPE'] = 'null'  # or 'redis', 'mongodb', etc.
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    Session(app)

    # Register blueprints
    app.register_blueprint(main_bp)

    # Configure CORS
    CORS(app)

    # Additional configurations
    app.config.update(
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=True,
        SECRET_KEY=secrets.token_urlsafe()  # Ensure you use a strong secret key
    )

    return app
