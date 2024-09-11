from flask import Flask, request, jsonify, redirect, url_for, session, render_template, Response, abort
import requests
import json
import os
import secrets
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Geração de uma chave secreta segura para a sessão

# Caminhos para arquivos de dados
JSON_FILE_PATH = 'uniques_data.json'
FAVORITES_FILE_PATH = 'favorites.json'
ITEMS_PER_PAGE = 6  # Ajuste conforme necessário
PLACEHOLDER_IMAGE_URL = 'https://via.placeholder.com/200x200'

# Rota para logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_info', None)
    return redirect(url_for('index'))

# Rota para login com Battle.net
@app.route('/login')
def battle_net_login():
    state = secrets.token_urlsafe()
    session['oauth_state'] = state
    client_id = '61903ba666634e469e7b4977be4972f4'
    redirect_uri = 'https://uniques-diablo4.vercel.app/callback'
    scope = 'openid'
    auth_url = (
        f"https://battle.net/oauth/authorize?client_id={client_id}"
        f"&redirect_uri={redirect_uri}&response_type=code"
        f"&scope={scope}&state={state}"
    )
    return redirect(auth_url)

# Rota de callback após autenticação
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

    # Obter o token de acesso
    response = requests.post(token_url, data=payload)
    if response.status_code != 200:
        return "Failed to obtain access token", 500

    token_data = response.json()
    access_token = token_data.get('access_token')
    if not access_token:
        return "Access token not received", 500

    # Obter informações do usuário
    user_info_url = 'https://oauth.battle.net/userinfo'
    user_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
    if user_response.status_code != 200:
        return "Failed to get user information", 500

    user_info = user_response.json()
    session['user_info'] = user_info
    print("Sessão após o callback:", session)
    
    return redirect(url_for('index'))

# Rota para atualizar dados locais
@app.route('/update')
def update():
    update_local_data()
    return jsonify({'status': 'Data updated successfully'}), 200

# Rota para a página inicial
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
    favorites = load_favorites_for_user(user_info['id']) if user_info else []

    print(paginated_uniques)
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

# Rota para adicionar um item aos favoritos
@app.route('/add_favorite', methods=['POST'])
def add_favorite():
    data = request.json
    item_name = data.get('item_name')
    user_info = session.get('user_info')

    print("Sessão na add_favorite:", session)
    print("Informações do usuário:", user_info)

    if not user_info:
        return jsonify({'error': 'User not logged in', 'success': False}), 403

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    user_id = user_info.get('id')
    add_to_favorites(user_id, item_name)
    return jsonify({'status': 'Favorite added successfully', 'success': True}), 200

# Rota para remover um item dos favoritos
@app.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    data = request.json
    item_name = data.get('item_name')
    user_info = session.get('user_info')
    print("Sessão na remove_favorite:", session)
    print("Informações do usuário:", user_info)

    if not user_info:
        return jsonify({'error': 'User not logged in', 'success': False}), 403

    if not item_name:
        return jsonify({'error': 'Item name is required', 'success': False}), 400

    user_id = user_info.get('id')
    remove_from_favorites(user_id, item_name)
    return jsonify({'status': 'Favorite removed successfully', 'success': True}), 200

# Rota para obter a imagem do item
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

# Rota para servir uma imagem de placeholder
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

# Rota para sugestões de busca
@app.route('/search_suggestions')
def search_suggestions():
    query = request.args.get('q', '').lower()
    uniques = get_uniques()
    suggestions = [unique['name'] for unique in uniques if query in unique['name'].lower()]
    return jsonify(suggestions)

# Função para atualizar dados locais
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
                codex_name_to_item[label]['description'] = item.get('description', 'Descrição não disponível')
                codex_name_to_item[label]['class'] = item.get('class', 'Classe não disponível')

    updated_data.extend(codex_name_to_item.values())

    with open(JSON_FILE_PATH, 'w') as f:
        json.dump(updated_data, f, indent=4)

# Função para carregar dados do arquivo
def load_data_from_file():
    try:
        with open(JSON_FILE_PATH, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# Função para buscar dados com retry
def fetch_data_with_retry(url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                print(f"Failed to fetch data from {url} after {retries} attempts.")
                raise e

# Função para carregar favoritos do usuário
def load_favorites_for_user(user_id):
    try:
        with open(FAVORITES_FILE_PATH, 'r') as f:
            favorites_data = json.load(f)
    except FileNotFoundError:
        favorites_data = {}

    return favorites_data.get(user_id, [])

# Função para adicionar item aos favoritos
def add_to_favorites(user_id, item_name):
    favorites = load_favorites_for_user(user_id)
    if item_name not in favorites:
        favorites.append(item_name)
        update_favorites(user_id, favorites)

# Função para remover item dos favoritos
def remove_from_favorites(user_id, item_name):
    favorites = load_favorites_for_user(user_id)
    if item_name in favorites:
        favorites.remove(item_name)
        update_favorites(user_id, favorites)

# Função para atualizar o arquivo de favoritos
def update_favorites(user_id, favorites):
    try:
        with open(FAVORITES_FILE_PATH, 'r') as f:
            favorites_data = json.load(f)
    except FileNotFoundError:
        favorites_data = {}

    favorites_data[user_id] = favorites
    with open(FAVORITES_FILE_PATH, 'w') as f:
        json.dump(favorites_data, f, indent=4)

# Função para obter os únicos
def get_uniques():
    return load_data_from_file()

if __name__ == '__main__':
    app.run(debug=True)
