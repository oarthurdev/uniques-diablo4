import requests
import json
import os
import time
import jwt
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

def decode_jwt_token(token, secret_key=None, algorithms=None):
    """
    Decodes a JWT token using the provided secret key and algorithms.

    Args:
        token (str): The JWT token to decode.
        secret_key (str, optional): The secret key used to decode the token. If None, uses the app's secret key.
        algorithms (list, optional): A list of algorithms to use for decoding. Defaults to None which means 'HS256'.

    Returns:
        dict: The decoded token payload if successful.
        None: If the token is invalid or decoding fails.
    """
    if secret_key is None:
        secret_key = app.config.get('SECRET_KEY', 'your_default_secret_key')
    
    if algorithms is None:
        algorithms = ['HS256']  # Default algorithm
    
    try:
        # Decode the JWT token
        decoded_token = jwt.decode(token, secret_key, algorithms=algorithms)
        print(token)
        return decoded_token
    except jwt.ExpiredSignatureError:
        print("Token has expired")
    except jwt.InvalidTokenError:
        print("Invalid token")
    except Exception as e:
        print(f"An error occurred: {e}")

    return None

def create_access_token(identity, secret_key=None, algorithm='HS256'):
    """
    Creates a JWT token.

    Args:
        identity (dict): The payload to encode into the JWT token.
        secret_key (str, optional): The secret key used to sign the token. If None, uses the app's secret key.
        algorithm (str, optional): The algorithm used for signing. Defaults to 'HS256'.

    Returns:
        str: The encoded JWT token.
    """
    if secret_key is None:
        secret_key = app.config.get('SECRET_KEY', 'your_default_secret_key')

    # Create the token
    token = jwt.encode(identity, secret_key, algorithm=algorithm)
    return token