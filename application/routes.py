from flask import Blueprint, request, jsonify, redirect, session, url_for, render_template, Response, abort, make_response
import requests
from flask_jwt_extended import create_access_token, decode_token, jwt_required, get_jwt_identity, unset_jwt_cookies, set_access_cookies
from .utils import fetch_data_with_retry, save_data_to_file, load_data_from_file, decode_token
from .models import db, User, Favorite
from .config import Config
import secrets

bp = Blueprint('main', __name__)

@bp.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@bp.route('/check_auth', methods=['GET'])
@jwt_required()
def check_auth():
    token = get_jwt_token_from_header()
    
    if token is None:
        return jsonify({'loggedIn': False}), 200
    
    decoded_token = decode_token(token)
    sub = decoded_token.get('sub')
    user_id = sub['user_info']['id']
    user = User.query.get(user_id)
    
    if user:
        return jsonify({
            'loggedIn': True,
            'battleTag': user.data.get('battletag', 'Desconhecido')
        }), 200
    else:
        return jsonify({'loggedIn': False}), 200

@bp.route('/logout', methods=['POST'])
def logout():
    response = jsonify({'status': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response, 200

@bp.route('/login')
def battle_net_login():
    state = secrets.token_urlsafe()  # Gera um estado seguro
    session['oauth_state'] = state  # Armazena o estado na sessão
    client_id = '61903ba666634e469e7b4977be4972f4'
    redirect_uri = url_for('main.callback', _external=True)
    scope = 'openid'
    auth_url = (
        f"https://battle.net/oauth/authorize?client_id={client_id}"
        f"&redirect_uri={redirect_uri}&response_type=code"
        f"&scope={scope}&state={state}"
    )
    return redirect(auth_url)

@bp.route('/callback')
def callback():
    state = request.args.get('state')
    code = request.args.get('code')
    if not code:
        return "Authorization code missing", 400

    if state != session.get('oauth_state'):
        return "State parameter mismatch", 400

    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': f"{Config.BASE_URL}/callback",
        'client_id': Config.BATTLE_NET_CLIENT_ID,
        'client_secret': Config.BATTLE_NET_CLIENT_SECRET
    }

    try:
        response = requests.post(Config.OAUTH_TOKEN_URL, data=payload)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get('access_token')

        user_info_response = requests.get(Config.OAUTH_USERINFO_URL, headers={'Authorization': f'Bearer {access_token}'})
        user_info_response.raise_for_status()
        user_info = user_info_response.json()

    except requests.RequestException:
        return "Failed to obtain user information", 500

    user_id = user_info.get('id')
    existing_user = User.query.get(user_id)

    if not existing_user:
        new_user = User(id=user_id, data=user_info, jwt_token='')  # Cria o usuário com um token vazio
        db.session.add(new_user)
        db.session.commit()
        existing_user = new_user

    jwt_token = create_access_token(identity={'user_info': user_info})
    existing_user.jwt_token = jwt_token  # Atualiza o token JWT no banco de dados
    db.session.commit()

    response = make_response(redirect(url_for('main.index')))
    response.set_cookie(
        'access_token_cookie',
        jwt_token,
        httponly=False,
        secure=True,
        max_age=60*60*24*7  # 7 dias
    )

    return response

def get_jwt_token_from_header():
    auth_header = request.headers.get('Authorization', None)
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[len('Bearer '):]
    return None

@bp.route('/')
@jwt_required(optional=True)
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
    total_pages = (total_items + Config.ITEMS_PER_PAGE - 1) // Config.ITEMS_PER_PAGE
    start = (page - 1) * Config.ITEMS_PER_PAGE
    end = start + Config.ITEMS_PER_PAGE
    paginated_uniques = filtered_uniques[start:end]

    all_classes = sorted(set(unique['class'] for unique in uniques if unique['class'] and unique['class'] != 'Classe não disponível'))

    user_info = None
    favorites = []

    token = request.cookies.get('access_token_cookie')
    if not token:
        # Verifica o token no banco de dados se não estiver no cookie
        user_id = request.args.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user and user.jwt_token:
                token = user.jwt_token

    if token:
        try:
            decoded_token = decode_token(token)
            sub = decoded_token.get('sub')
            if sub and 'user_info' in sub:
                user_info = {'id': sub['user_info']['id'], 'battletag': sub['user_info']['battletag']}
                favorites = [fav.item_name for fav in Favorite.query.filter_by(user_id=sub['user_info']['id']).all()]
        except Exception as e:
            print(f"Error extracting user info: {e}")

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

@bp.route('/add_favorite', methods=['POST'])
@jwt_required()
def add_favorite():
    data = request.json
    print(data)
    item_name = data.get('item_name')
    token = get_jwt_token_from_header()

    print(token)
    if token:
        decoded_token = decode_token(token)
        
        sub = decoded_token.get('sub')
        user_id = sub['user_info']['id']
        
    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    if not Favorite.query.filter_by(user_id=user_id, item_name=item_name).first():
        new_favorite = Favorite(user_id=user_id, item_name=item_name)
        db.session.add(new_favorite)
        db.session.commit()

    return jsonify({'status': 'Favorite added successfully', 'success': True}), 200

@bp.route('/remove_favorite', methods=['POST'])
@jwt_required()
def remove_favorite():
    data = request.json
    item_name = data.get('item_name')
    token = get_jwt_token_from_header()

    if token:
        decoded_token = decode_token(token)
        sub = decoded_token.get('sub')
        user_id = sub['user_info']['id']

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    favorite = Favorite.query.filter_by(user_id=user_id, item_name=item_name).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()

    return jsonify({'status': 'Favorite removed successfully', 'success': True}), 200

@bp.route('/image')
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

@bp.route('/update')
def update():
    update_local_data()
    return jsonify({'status': 'Data updated successfully'}), 200

@bp.route('/search_suggestions')
def search_suggestions():
    query = request.args.get('q', '').lower()
    uniques = get_uniques()
    suggestions = [unique['name'] for unique in uniques if query in unique['name'].lower()]
    return jsonify(suggestions)

def serve_placeholder_image():
    try:
        response = requests.get(Config.PLACEHOLDER_IMAGE_URL, stream=True)
        if response.status_code == 200:
            return Response(response.content, mimetype=response.headers['Content-Type'])
        else:
            return abort(404, description='Placeholder image not available')
    except requests.RequestException:
        return abort(500, description='Erro ao obter a imagem de placeholder')

def update_local_data():
    codex_data = fetch_data_with_retry(Config.CODDEX_API_URL)
    uniques_data = fetch_data_with_retry(Config.UNIQUES_API_URL)

    codex_name_to_item = {}
    if codex_data:
        for item in codex_data:
            item_type = 'Mythic' if item.get('mythic', False) else 'Unique'
            codex_name_to_item[item.get('label', '').lower()] = {
                'class': item.get('class', 'Generic'),
                'description': item.get('description', 'Descrição não disponível'),
                'image_url': item.get('image_url', Config.PLACEHOLDER_IMAGE_URL),
                'type': item_type
            }

    existing_data = load_data_from_file()
    existing_labels = {item.get('label', '').lower() for item in existing_data}

    updated_data = []

    for item in codex_data:
        if item.get('type') == 'Unique':
            label = item.get('label', '').lower()
            if label in codex_name_to_item:
                codex_name_to_item[label]['image_url'] = item.get('image_url', Config.PLACEHOLDER_IMAGE_URL)
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
                'class': item.get('class', 'Unknown'),
                'description': item.get('description', 'No description available'),
                'image_url': item.get('image_url', Config.PLACEHOLDER_IMAGE_URL)
            })

    save_data_to_file(updated_data)

def get_uniques():
    data = load_data_from_file()
    return [
        {
            'name': item.get('label', 'Nome não disponível').capitalize(),
            'type': item.get('type', 'Tipo não disponível').capitalize(),
            'class': item.get('class', 'Classe não disponível').capitalize(),
            'power': item.get('description', 'Poder não disponível'),
            'image_url': item.get('image_url', Config.PLACEHOLDER_IMAGE_URL)
        }
        for item in data
        if item.get('type') in ['Mythic', 'Unique']
    ]
