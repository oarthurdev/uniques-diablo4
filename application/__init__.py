from flask import Flask
from .models import db
from .routes import bp as main_bp
from .config import Config
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)
    
    with app.app_context():
        db.create_all()

    app.config['JWT_SECRET_KEY'] = Config.SECRET_KEY  # Alterar para o seu segredo real
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/'  # Caminho onde o cookie é acessível
    app.config['JWT_COOKIE_SECURE'] = True  # Defina como True em produção se estiver usando HTTPS
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # Se você estiver usando proteção CSRF com JWT
    app.config.from_object(Config)

    jwt = JWTManager(app)
    
    db.init_app(app)
    app.register_blueprint(main_bp)
    return app
