from flask import Blueprint, request, jsonify, redirect, url_for, session, render_template, Response, abort
import requests
from .models import db, User, Favorite
from .utils import fetch_data_with_retry, save_data_to_file, load_data_from_file

bp = Blueprint('main', __name__)

@bp.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@bp.route('/logout', methods=['POST'])
def logout():
    session.pop('user_info', None)
    return redirect(url_for('main.index'))

@bp.route('/login')
def battle_net_login():
    state = secrets.token_urlsafe()
    session['oauth_state'] = state
    auth_url = (
        f"https://battle.net/oauth/authorize?client_id={app.config['BATTLE_NET_CLIENT_ID']}"
        f"&redirect_uri={app.config['BASE_URL']}/callback&response_type=code"
        f"&scope=openid&state={state}"
    )
    return redirect(auth_url)

@bp.route('/callback')
def callback():
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "State parameter mismatch", 400

    code = request.args.get('code')
    if not code:
        return "Authorization code missing", 400

    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': f"{app.config['BASE_URL']}/callback",
        'client_id': app.config['BATTLE_NET_CLIENT_ID'],
        'client_secret': app.config['BATTLE_NET_CLIENT_SECRET']
    }

    try:
        response = requests.post(app.config['OAUTH_TOKEN_URL'], data=payload)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get('access_token')

        user_info_response = requests.get(app.config['OAUTH_USERINFO_URL'], headers={'Authorization': f'Bearer {access_token}'})
        user_info_response.raise_for_status()
        user_info = user_info_response.json()
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

    return redirect(url_for('main.index'))

@bp.route('/')
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
    total_pages = (total_items + app.config['ITEMS_PER_PAGE'] - 1) // app.config['ITEMS_PER_PAGE']
    start = (page - 1) * app.config['ITEMS_PER_PAGE']
    end = start + app.config['ITEMS_PER_PAGE']
    paginated_uniques = filtered_uniques[start:end]

    all_classes = sorted(set(unique['class'] for unique in uniques if unique['class'] and unique['class'] != 'Classe não disponível'))

    user_info = session.get('user_info')
    favorites = []
    if user_info:
        user_id = user_info['id']
        favorites = [fav.item_name for fav in Favorite.query.filter_by(user_id=user_id).all()]

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
def add_favorite():
    data = request.json
    item_name = data.get('item_name')
    user_info = session.get('user_info')

    if not user_info:
        return jsonify({'error': 'User not logged in', 'success': False}), 403

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    user_id = user_info.get('id')
    if not Favorite.query.filter_by(user_id=user_id, item_name=item_name).first():
        new_favorite = Favorite(user_id=user_id, item_name=item_name)
        db.session.add(new_favorite)
        db.session.commit()

    return jsonify({'status': 'Favorite added successfully', 'success': True}), 200

@bp.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    data = request.json
    item_name = data.get('item_name')
    user_info = session.get('user_info')

    if not user_info:
        return jsonify({'error': 'User not logged in', 'success': False}), 403

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    user_id = user_info['id']
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
        response = requests.get(app.config['PLACEHOLDER_IMAGE_URL'], stream=True)
        if response.status_code == 200:
            return Response(response.content, mimetype=response.headers['Content-Type'])
        else:
            return abort(404, description='Placeholder image not available')
    except requests.RequestException:
        return abort(500, description='Erro ao obter a imagem de placeholder')

def update_local_data():
    codex_data = fetch_data_with_retry(app.config['CODDEX_API_URL'])
    uniques_data = fetch_data_with_retry(app.config['UNIQUES_API_URL'])

    codex_name_to_item = {}
    if codex_data:
        for item in codex_data:
            item_type = 'Mythic' if item.get('mythic', False) else 'Unique'
            codex_name_to_item[item.get('label', '').lower()] = {
                'class': item.get('class', 'Generic'),
                'description': item.get('description', 'Descrição não disponível'),
                'image_url': item.get('image_url', app.config['PLACEHOLDER_IMAGE_URL']),
                'type': item_type
            }

    existing_data = load_data_from_file()
    existing_labels = {item.get('label', '').lower() for item in existing_data}

    updated_data = []

    for item in codex_data:
        if item.get('type') == 'Unique':
            label = item.get('label', '').lower()
            if label in codex_name_to_item:
                codex_name_to_item[label]['image_url'] = item.get('image_url', app.config['PLACEHOLDER_IMAGE_URL'])
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
                'image_url': item.get('image_url', app.config['PLACEHOLDER_IMAGE_URL'])
            })
        else:
            for updated_item in updated_data:
                if updated_item.get('label', '').lower() == label:
                    updated_item['image_url'] = item.get('image_url', app.config['PLACEHOLDER_IMAGE_URL'])
                    updated_item['type'] = item_type

    save_data_to_file(updated_data)

def get_uniques():
    data = load_data_from_file()
    return [
        {
            'name': item.get('label', 'Nome não disponível').capitalize(),
            'type': item.get('type', 'Tipo não disponível').capitalize(),
            'class': item.get('class', 'Classe não disponível').capitalize(),
            'power': item.get('description', 'Poder não disponível'),
            'image_url': item.get('image_url', app.config['PLACEHOLDER_IMAGE_URL'])
        }
        for item in data
        if item.get('type') in ['Mythic', 'Unique']
    ]
