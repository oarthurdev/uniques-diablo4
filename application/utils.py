import requests
import json
import os
import time
from flask import current_app as app

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
    with open(app.config['JSON_FILE_PATH'], 'w') as file:
        json.dump(data, file, indent=4)

def load_data_from_file():
    if os.path.exists(app.config['JSON_FILE_PATH']):
        with open(app.config['JSON_FILE_PATH'], 'r') as file:
            return json.load(file)
    return []

def decode_token(token):
    try:
        return decode_token(token, app.config['JWT_SECRET_KEY'])
    except Exception as e:
        print(f"Erro ao decodificar o token: {e}")
        return None
