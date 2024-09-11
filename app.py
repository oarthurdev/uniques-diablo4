from flask import Flask, request, jsonify, redirect, url_for, session, render_template, Response, abort
import requests
import json
import os
import time
import secrets
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Em produção, use variáveis de ambiente
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://uniques-d4_owner:6oKHsYply1ZB@ep-aged-brook-a509z7ni.us-east-2.aws.neon.tech/uniques-d4?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=30)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.JSON)

class Favorite(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    item_name = db.Column(db.String, primary_key=True)
    user = db.relationship('User', backref='favorites')

JSON_FILE_PATH = 'uniques_data.json'
ITEMS_PER_PAGE = 6
PLACEHOLDER_IMAGE_URL = 'https://via.placeholder.com/200x200'

with app.app_context():
    db.create_all()

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_info', None)
    return redirect(url_for('index'))

@app.route('/login')
def battle_net_login():
    state = secrets.token_urlsafe()
    session['oauth_state'] = state
    client_id = '61903ba666634e469e7b4977be4972f4'
    redirect_uri = 'https://uniques-diablo4.vercel.app/callback'  # Atualize conforme necessário
    scope = 'openid'
    auth_url = (
        f"https://battle.net/oauth/authorize?client_id={client_id}"
        f"&redirect_uri={redirect_uri}&response_type=code"
        f"&scope={scope}&state={state}"
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "State parameter mismatch", 400

    code = request.args.get('code')
    if not code:
        return "Authorization code missing", 400

    client_id = '61903ba666634e469e7b4977be4972f4'
    client_secret = 'bc4TrOFgi6sO45EWpCWKFVdnwDAEfyyv'
    redirect_uri = "https://uniques-diablo4.vercel.app/callback"
    token_url = 'https://oauth.battle.net/token'
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret
    }

    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get('access_token')
        
        user_info_url = 'https://oauth.battle.net/userinfo'
        user_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
        user_response.raise_for_status()
        user_info = user_response.json()
    except requests.RequestException:
        return "Failed to obtain user information", 500

    session['user_info'] = user_info
    session.permanent = True

    user_id = user_info.get('id')
    existing_user = User.query.get(user_id)

    if not existing_user:
        new_user = User(id=user_id, data=user_info)
        db.session.add(new_user)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/')
def index():
    uniques = get_uniques() or []
    filter_class = request.args.get('class', '')
    filter_name = request.args.get('name', '').lower()
    page = int(request.args.get('page', 1))

    filtered_uniques = [
        unique for unique in uniques
        if (not filter_class or unique['class'].lower() == filter_class.lower()) and 
        (not filter_name or filter_name in unique['name'].lower())
    ]

    total_items = len(filtered_uniques)
    total_pages = (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
    start = (page - 1) * ITEMS_PER_PAGE
    end = start + ITEMS_PER_PAGE
    paginated_uniques = filtered_uniques[start:end]

    all_classes = sorted(set(unique['class'] for unique in uniques if unique['class'] and unique['class'] != 'Classe não disponível'))

    user_info = session.get('user_info')
    if user_info:
        user_id = user_info['id']
        favorites = Favorite.query.filter_by(user_id=user_id).all()
        favorites = [fav.item_name for fav in favorites]
    else:
        favorites = []

    return render_template(
        'index.html',
        uniques=paginated_uniques,
        all_classes=all_classes,
        filter_class=filter_class,
        filter_name=filter_name,
        page=page,
        total_pages=total_pages,
        user_info=user_info,
        favorites=favorites
    )

@app.route('/add_favorite', methods=['POST'])
def add_favorite():
    data = request.json
    item_name = data.get('item_name')
    user_info = session.get('user_info')

    if not user_info:
        return jsonify({'error': 'User not logged in', 'success': False}), 403

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    user_id = user_info.get('id')
    existing_favorite = Favorite.query.filter_by(user_id=user_id, item_name=item_name).first()
    if not existing_favorite:
        new_favorite = Favorite(user_id=user_id, item_name=item_name)
        db.session.add(new_favorite)
        db.session.commit()

    return jsonify({'status': 'Favorite added successfully', 'success': True}), 200

@app.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    data = request.json
    item_name = data.get('item_name')
    user_info = session.get('user_info')

    if not user_info:
        return jsonify({'error': 'User not logged in', 'success': False}), 403

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    user_id = user_info['id']
    existing_favorite = Favorite.query.filter_by(user_id=user_id, item_name=item_name).first()
    if existing_favorite:
        db.session.delete(existing_favorite)
        db.session.commit()

    return jsonify({'status': 'Favorite removed successfully', 'success': True}), 200

@app.route('/image')
def get_image():
    name = request.args.get('name', '').capitalize()
    uniques = get_uniques() or []
    
    for unique in uniques:
        if unique['name'] == name:
            image_url = unique['image_url']
            try:
                response = requests.get(image_url, stream=True)
                if response.status_code == 200:
                    return Response(response.content, mimetype=response.headers['Content-Type'])
                else:
                    return serve_placeholder_image()
            except requests.RequestException:
                return serve_placeholder_image()

    return abort(404, description='Item não encontrado')

@app.route('/update')
def update():
    update_local_data()
    return jsonify({'status': 'Data updated successfully'}), 200

@app.route('/serve_placeholder')
def serve_placeholder_image():
    try:
        response = requests.get(PLACEHOLDER_IMAGE_URL, stream=True)
        if response.status_code == 200:
            return Response(response.content, mimetype=response.headers['Content-Type'])
        else:
            return abort(404, description='Placeholder image not available')
    except requests.RequestException:
        return abort(500, description='Erro ao obter a imagem de placeholder')

@app.route('/search_suggestions')
def search_suggestions():
    query = request.args.get('q', '').lower()
    uniques = get_uniques()
    suggestions = [unique['name'] for unique in uniques if query in unique['name'].lower()]
    return jsonify(suggestions)

def fetch_data_with_retry(url, retries=5, delay=1):
    for i in range(retries):
        try:
            response = requests.get(url)
            if response.status_code == 429:
                time.sleep(delay)
                delay *= 2
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"RequestException: {e}")
            time.sleep(delay)
    return []

def save_data_to_file(data):
    with open(JSON_FILE_PATH, 'w') as file:
        json.dump(data, file, indent=4)

def load_data_from_file():
    if os.path.exists(JSON_FILE_PATH):
        with open(JSON_FILE_PATH, 'r') as file:
            return json.load(file)
    return []

def update_local_data():
    codex_api_url = 'https://d4api.dev/api/codex'
    codex_data = fetch_data_with_retry(codex_api_url)
    
    uniques_api_url = 'https://d4api.dev/api/uniques'
    uniques_data = fetch_data_with_retry(uniques_api_url)
    
    codex_name_to_item = {}
    if codex_data:
        for item in codex_data:
            item_type = 'Mythic' if item.get('mythic', False) else 'Unique'
            codex_name_to_item[item.get('label', '').lower()] = {
                'class': item.get('class', 'Generic'),
                'description': item.get('description', 'Descrição não disponível'),
                'image_url': item.get('image_url', 'https://via.placeholder.com/200x200'),
                'type': item_type
            }
    
    existing_data = load_data_from_file()
    existing_labels = {item.get('label', '').lower() for item in existing_data}

    updated_data = []

    for item in codex_data:
        if item.get('type') == 'Unique':
            label = item.get('label', '').lower()
            if label in codex_name_to_item:
                codex_name_to_item[label]['image_url'] = item.get('image_url', 'https://via.placeholder.com/200x200')
                updated_data.append({
                    'type': codex_name_to_item[label]['type'],
                    'label': item.get('label', ''),
                    'class': codex_name_to_item[label]['class'],
                    'description': codex_name_to_item[label]['description'],
                    'image_url': codex_name_to_item[label]['image_url']
                })

    for item in uniques_data:
        label = item.get('name', '').lower()
        item_type = 'Mythic' if item.get('mythic', False) else 'Unique'
        if label not in existing_labels:
            updated_data.append({
                'type': item_type,
                'label': item.get('name', ''),
                'class': item.get('class', 'Generic'),
                'description': item.get('description', 'Descrição não informada.'),
                'image_url': item.get('image_url', 'https://via.placeholder.com/200x200')
            })
        else:
            for updated_item in updated_data:
                if updated_item.get('label', '').lower() == label:
                    updated_item['image_url'] = item.get('image_url', 'https://via.placeholder.com/200x200')
                    updated_item['type'] = item_type

    save_data_to_file(updated_data)

def get_uniques():
    data = load_data_from_file()
    uniques = [
        {
            'name': item.get('label', 'Nome não disponível').capitalize(),
            'type': item.get('type', 'Tipo não disponível').capitalize(),
            'class': item.get('class', 'Classe não disponível').capitalize(),
            'power': item.get('description', 'Poder não disponível'),
            'image_url': item.get('image_url', 'https://via.placeholder.com/200x200')
        }
        for item in data
        if item.get('type') in ['Mythic', 'Unique']
    ]
    return uniques

if __name__ == '__main__':
    app.run(debug=True)
