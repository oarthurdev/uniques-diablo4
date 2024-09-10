from flask import abort, Flask, render_template, Response, request, session, url_for, redirect, jsonify
import requests
import json
import os
import time
import secrets

JSON_FILE_PATH = 'uniques_data.json'
ITEMS_PER_PAGE = 6  # Ajuste conforme necessário
PLACEHOLDER_IMAGE_URL = 'https://via.placeholder.com/200x200'
FAVORITES_FILE_PATH = 'favorites.json'

def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)  # Necessário para sessões

    @app.route('/logout', methods=['POST'])
    def logout():
        session.pop('user_info', None)  # Remove as informações do usuário da sessão
        return redirect(url_for('index'))  # Redireciona para a página inicial após o logout
    
    @app.route('/login')
    def battle_net_login():
        state = secrets.token_urlsafe()  # Gera um estado seguro
        session['oauth_state'] = state  # Armazena o estado na sessão
        client_id = '61903ba666634e469e7b4977be4972f4'
        redirect_uri = url_for('callback', _external=True)
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

        # Trocar o código de autorização por um token de acesso
        client_id = '61903ba666634e469e7b4977be4972f4'
        client_secret = 'bc4TrOFgi6sO45EWpCWKFVdnwDAEfyyv'  # Substitua pelo seu client_secret
        redirect_uri = url_for('callback', _external=True)
        token_url = 'https://oauth.battle.net/token'
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'client_secret': client_secret
        }

        response = requests.post(token_url, data=payload)
        if response.status_code != 200:
            return "Failed to obtain access token", 500
        
        token_data = response.json()
        access_token = token_data.get('access_token')
        if not access_token:
            return "Access token not received", 500
        
        # Obter informações do perfil do usuário
        user_info_url = 'https://oauth.battle.net/userinfo'
        user_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
        if user_response.status_code != 200:
            return "Failed to get user information", 500
        
        user_info = user_response.json()
        session['user_info'] = user_info
        
        return redirect(url_for('index'))

    @app.route('/update')
    def update():
        update_local_data()
        return jsonify({'status': 'Data updated successfully'}), 200

    @app.route('/')
    def index():
        uniques = get_uniques() or []  # Garante que uniques seja uma lista, mesmo em caso de erro
        filter_class = request.args.get('class', '')
        filter_name = request.args.get('name', '').lower()
        page = int(request.args.get('page', 1))

        # Filtragem
        filtered_uniques = [
            unique for unique in uniques
            if (not filter_class or unique['class'].lower() == filter_class.lower()) and 
            (not filter_name or filter_name in unique['name'].lower())
        ]

        # Paginação
        total_items = len(filtered_uniques)
        total_pages = (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
        start = (page - 1) * ITEMS_PER_PAGE
        end = start + ITEMS_PER_PAGE
        paginated_uniques = filtered_uniques[start:end]

        all_classes = sorted(set(unique['class'] for unique in uniques if unique['class'] and unique['class'] != 'Classe não disponível'))

        user_info = session.get('user_info')
        favorites = load_favorites_for_user(user_info['id']) if user_info else []

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
        data = request.json  # Captura os dados JSON da requisição
        item_name = data.get('item_name')
        user_info = session.get('user_info')
        if not user_info:
            return jsonify({'error': 'User not logged in', 'success': False}), 403

        if not item_name:
            return jsonify({'error': 'Item name is required', 'success': False}), 400

        user_id = user_info['id']
        add_to_favorites(user_id, item_name)
        return jsonify({'status': 'Favorite added successfully', 'success': True}), 200

    @app.route('/remove_favorite', methods=['POST'])
    def remove_favorite():
        data = request.json  # Captura os dados JSON da requisição
        item_name = data.get('item_name')
        user_info = session.get('user_info')
        if not user_info:
            return jsonify({'error': 'User not logged in', 'success': False}), 403

        if not item_name:
            return jsonify({'error': 'Item name is required', 'success': False}), 400

        user_id = user_info['id']
        remove_from_favorites(user_id, item_name)
        return jsonify({'status': 'Favorite removed successfully', 'success': True}), 200

    @app.route('/image')
    def get_image():
        name = request.args.get('name', '').capitalize()
        uniques = get_uniques() or []
        
        for unique in uniques:
            if unique['name'] == name:
                image_url = unique['image_url']
                try:
                    # Fazer uma solicitação GET para a URL da imagem
                    response = requests.get(image_url, stream=True)
                    # Verificar se a solicitação foi bem-sucedida
                    if response.status_code == 200:
                        # Retornar a imagem com o tipo de conteúdo apropriado
                        return Response(response.content, mimetype=response.headers['Content-Type'])
                    else:
                        # Tratar erros na solicitação da imagem, retornando o placeholder
                        return serve_placeholder_image()
                except requests.RequestException as e:
                    # Tratar exceções relacionadas à solicitação
                    return serve_placeholder_image()

        return abort(404, description='Item não encontrado')

    @app.route('/serve_placeholder')
    def serve_placeholder_image():
        try:
            # Fazer uma solicitação GET para a URL do placeholder
            response = requests.get(PLACEHOLDER_IMAGE_URL, stream=True)
            # Verificar se a solicitação foi bem-sucedida
            if response.status_code == 200:
                return Response(response.content, mimetype=response.headers['Content-Type'])
            else:
                return abort(404, description='Placeholder image not available')
        except requests.RequestException as e:
            return abort(500, description=f'Erro ao obter a imagem de placeholder: {str(e)}')

    @app.route('/search_suggestions')
    def search_suggestions():
        query = request.args.get('q', '').lower()
        uniques = get_uniques()  # Supondo que você tenha a função get_uniques
        suggestions = [unique['name'] for unique in uniques if query in unique['name'].lower()]
        return jsonify(suggestions)
    
    # Initialize data on app startup
    update_local_data()

    return app

def fetch_data_with_retry(url, retries=5, delay=1):
    for i in range(retries):
        try:
            response = requests.get(url)
            if response.status_code == 429:
                time.sleep(delay)
                delay *= 2  # Exponential backoff
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"RequestException: {e}")
            break
    return []

def save_data_to_file(data):
    with open(JSON_FILE_PATH, 'w') as file:
        json.dump(data, file, indent=4)

def load_data_from_file():
    if os.path.exists(JSON_FILE_PATH):
        with open(JSON_FILE_PATH, 'r') as file:
            return json.load(file)
    return []

def load_favorites_for_user(user_id):
    if os.path.exists(FAVORITES_FILE_PATH):
        with open(FAVORITES_FILE_PATH, 'r') as file:
            favorites_data = json.load(file)
            return favorites_data.get(str(user_id), [])
    return []

def save_favorites_for_user(user_id, favorites):
    if os.path.exists(FAVORITES_FILE_PATH):
        with open(FAVORITES_FILE_PATH, 'r') as file:
            favorites_data = json.load(file)
    else:
        favorites_data = {}

    favorites_data[str(user_id)] = favorites

    with open(FAVORITES_FILE_PATH, 'w') as file:
        json.dump(favorites_data, file, indent=4)

def add_to_favorites(user_id, item_name):
    favorites = load_favorites_for_user(user_id)
    if item_name not in favorites:
        favorites.append(item_name)
        print(f"Favorites after adding: {favorites}")
        save_favorites_for_user(user_id, favorites)
    else:
        print(f"Item '{item_name}' is already in favorites.")

def remove_from_favorites(user_id, item_name):
    favorites = load_favorites_for_user(user_id)
    if item_name in favorites:
        favorites.remove(item_name)
        print(f"Favorites after removing: {favorites}")
        save_favorites_for_user(user_id, favorites)
    else:
        print(f"Item '{item_name}' is not in favorites.")

def update_local_data():
    # Fetch codex data
    codex_api_url = 'https://d4api.dev/api/codex'
    codex_data = fetch_data_with_retry(codex_api_url)
    
    # Fetch uniques data
    uniques_api_url = 'https://d4api.dev/api/uniques'
    uniques_data = fetch_data_with_retry(uniques_api_url)
    
    # Map name to codex item
    codex_name_to_item = {}
    if codex_data:
        for item in codex_data:
            item_type = 'Mythic' if item.get('mythic', False) else 'Unique'
            codex_name_to_item[item.get('label', '').lower()] = {
                'class': item.get('class', 'Generic'),
                'description': item.get('description', 'Descrição não disponível'),
                'image_url': item.get('image_url', 'https://via.placeholder.com/200x200'),
                'type': item_type  # Default type
            }
    
    # Load existing data from file
    existing_data = load_data_from_file()
    existing_labels = {item.get('label', '').lower() for item in existing_data}

    # Create a list to store the updated data
    updated_data = []

    # Update codex data with image URLs
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

    # Add or update items from uniques_data
    for item in uniques_data:
        label = item.get('name', '').lower()
        item_type = 'Mythic' if item.get('mythic', False) else 'Unique'
        if label not in existing_labels:
            # Item is new, add it to the updated data
            updated_data.append({
                'type': item_type,
                'label': item.get('name', ''),
                'class': item.get('class', 'Generic'),
                'description': item.get('description', 'Descrição não informada.'),
                'image_url': item.get('image_url', 'https://via.placeholder.com/200x200')
            })
        else:
            # Update existing item with its image URL from uniques
            for updated_item in updated_data:
                if updated_item.get('label', '').lower() == label:
                    updated_item['image_url'] = item.get('image_url', 'https://via.placeholder.com/200x200')
                    updated_item['type'] = item_type  # Update the type based on mythic

    # Save updated data to file
    save_data_to_file(updated_data)

def get_uniques():
    data = load_data_from_file()
    uniques = [
        {
            'name': item.get('label', 'Nome não disponível').capitalize(),
            'type': item.get('type', 'Tipo não disponível').capitalize(),
            'class': item.get('class', 'Classe não disponível').capitalize(),
            'power': item.get('description', 'Poder não disponível'),
            'image_url': item.get('image_url', 'https://via.placeholder.com/200x200')  # URL da imagem já está no JSON
        }
        for item in data
        if item.get('type') in ['Mythic', 'Unique']
    ]
    return uniques

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
