import secrets
from datetime import timedelta

class Config:
    SECRET_KEY = secrets.token_hex(16)  # Em produção, use variáveis de ambiente
    ALG_JWT = ['HS256']
    SQLALCHEMY_DATABASE_URI = 'postgresql://uniques-d4_owner:6oKHsYply1ZB@ep-aged-brook-a509z7ni.us-east-2.aws.neon.tech/uniques-d4?sslmode=require'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    JSON_FILE_PATH = 'uniques_data.json'
    ITEMS_PER_PAGE = 6
    PLACEHOLDER_IMAGE_URL = 'https://via.placeholder.com/200x200'
    BASE_URL = 'https://uniques-diablo4.vercel.app'
    CODDEX_API_URL = 'https://d4api.dev/api/codex'
    UNIQUES_API_URL = 'https://d4api.dev/api/uniques'
    BATTLE_NET_CLIENT_ID = '61903ba666634e469e7b4977be4972f4'
    BATTLE_NET_CLIENT_SECRET = 'bc4TrOFgi6sO45EWpCWKFVdnwDAEfyyv'
    OAUTH_TOKEN_URL = 'https://oauth.battle.net/token'
    OAUTH_USERINFO_URL = 'https://oauth.battle.net/userinfo'
