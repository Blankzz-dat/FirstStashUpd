import string
import random
import secrets
import base64
import time
import sqlite3
import json
import ipaddress
import os
from flask import Flask, request, jsonify, send_file, render_template_string
from flask_sockets import Sockets
import requests

# Constants

DB_PATH = '/userdata.db'
WEBHOOK_URL = 'https://discord.com/api/webhooks/1386463011362836582/WAG8sMCuf9QihXkHFHAVsGgdsXO00mZI2TwIQqTzcBXN1P4QWnzlS16Y85gpsPMAJk3H'
ENABLE_RANDOM_TOKENS = True
trusted_public_ips = {'71.241.196.83', '72.44.48.182'}  # Add actual trusted IPs

# Initialize database
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                ip TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                custom_id TEXT NOT NULL,
                create_time REAL NOT NULL
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY
            )
        ''')
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {e}")

app = Flask(__name__)
init_db()
sockets = Sockets(app)

# Discord webhook logging middleware
@app.after_request
def log_to_discord(response):
    try:
        method = request.method
        url = request.url
        path = request.path
        headers = dict(request.headers)
        body = request.get_data(as_text=True)
        query_params = dict(request.args)
        status_code = response.status_code

        message = {
            'content': f"📡 **Request to: {path}**",
            'embeds': [{
                'title': 'Request Details',
                'fields': [
                    {'name': 'Method', 'value': method, 'inline': True},
                    {'name': 'Path', 'value': path, 'inline': True},
                    {'name': 'Status Code', 'value': str(status_code), 'inline': True},
                    {'name': 'Full URL', 'value': url, 'inline': False},
                    {'name': 'Query Params', 'value': f"```json\n{json.dumps(query_params, indent=2)}```" if query_params else '*(none)*', 'inline': False},
                    {'name': 'Headers', 'value': f"```json\n{json.dumps(headers, indent=2)}```", 'inline': False},
                    {'name': 'Body', 'value': f"```json\n{body}```" if body else '*(empty)*', 'inline': False}
                ],
                'color': 65280 if status_code < 400 else 16711680
            }]
        }

        requests.post(WEBHOOK_URL, json=message, timeout=5)
    except Exception as e:
        print(f"Failed to log to Discord: {e}")

    return response

# Helper functions
def generate_username():
    return 'Player+' + ''.join(random.choices(string.ascii_uppercase, k=6))

def generate_gameplay_loadout():
    try:
        with open('/econ_gameplay_items.json', 'r') as f:
            data = json.load(f)
        item_ids = [item['id'] for item in data if 'id' in item]
    except Exception as e:
        print(f"Failed to load econ_gameplay_items.json: {e}")
        item_ids = ['item_jetpack', 'item_flaregun', 'item_dynamite', 'item_tablet', 'item_flashlight_mega',
                   'item_plunger', 'item_crossbow', 'item_revolver', 'item_shotgun', 'item_pickaxe']

    children = []
    for _ in range(20):
        if random.random() < 0.7 and 'item_arena_pistol' in item_ids:
            selected_item = 'item_arena_pistol'
        else:
            selected_item = random.choice(item_ids)
        children.append({
            'itemID': selected_item,
            'scaleModifier': 100,
            'colorHue': random.randint(10, 111),
            'colorSaturation': random.randint(10, 111)
        })

    payload = {
        'objects': [{
            'collection': 'user_inventory',
            'key': 'gameplay_loadout',
            'permission_read': 1,
            'permission_write': 1,
            'value': json.dumps({
                'version': 1,
                'back': {
                    'itemID': 'item_backpack_large_base',
                    'scaleModifier': 120,
                    'colorHue': 50,
                    'colorSaturation': 50,
                    'children': children
                }
            })
        }]
    }
    return payload

def is_trusted_ip(ip_address):
    try:
        if ip_address in trusted_public_ips:
            return True

        ip = ipaddress.ip_address(ip_address)
        # Add your actual IP ranges here
        if ip.version == 4:
            return (ip in ipaddress.IPv4Network('192.168.1.0/24') or
                    ip in ipaddress.IPv4Network('10.0.0.0/8'))
        return False
    except ValueError:
        return False

def generate_unique_user_id():
    return secrets.token_hex(8) + '-' + secrets.token_hex(4) + '-' + secrets.token_hex(4) + '-' + secrets.token_hex(4) + '-' + secrets.token_hex(12)

def generate_custom_id():
    return ''.join(random.choices(string.digits, k=17))

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)

def get_or_create_user(ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # Check if IP is banned
        cur.execute('SELECT 1 FROM banned_ips WHERE ip = ?', (ip,))
        if cur.fetchone():
            conn.close()
            return None, True

        # Get existing user or create new one
        cur.execute('SELECT username, custom_id FROM users WHERE ip = ?', (ip,))
        result = cur.fetchone()

        if result:
            username, custom_id = result
            user_id = generate_unique_user_id()  # Generate new ID for existing user too
        else:
            if ip == '127.0.0.1':
                username = '<color=red>0x11'
            else:
                username = generate_username()
            custom_id = generate_custom_id()
            user_id = generate_unique_user_id()
            cur.execute('INSERT INTO users (ip, username, custom_id, create_time) VALUES (?, ?, ?, ?)',
                       (ip, username, custom_id, time.time()))
            conn.commit()

        conn.close()
        return {'username': username, 'custom_id': custom_id, 'user_id': user_id}, False
    except Exception as e:
        print(f"Database error in get_or_create_user: {e}")
        return None, False

def generate_jwt(user_id):
    try:
        header = {'alg': 'HS256', 'typ': 'JWT'}
        now = int(time.time())
        payload = {
            'tid': secrets.token_hex(16),
            'uid': user_id,
            'usn': secrets.token_hex(5),
            'vrs': {
                'authID': secrets.token_hex(20),
                'clientUserAgent': 'MetaQuest 1.16.3.1138_5edcbd98',
                'deviceID': secrets.token_hex(20),
                'loginType': 'meta_quest'
            },
            'exp': now + 72000,
            'iat': now
        }

        # Fixed: Use standalone function instead of nested
        def b64encode(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')

        signature = secrets.token_urlsafe(32)
        return f"{b64encode(header)}.{b64encode(payload)}.{signature}"
    except Exception as e:
        print(f"Error generating JWT: {e}")
        # Fallback token
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def generate_tokens():
    user_id = generate_unique_user_id()
    return {
        'token': generate_jwt(user_id),
        'refresh_token': generate_jwt(user_id)
    }

# Predefined responses
CLIENT_BOOTSTRAP_RESPONSE = {
    'payload': '{"updateType":"None","attestResult":"Valid","attestTokenExpiresAt":1820877961,"photonAppID":"856de1ba-bd6d-4656-be08-9a80c2115c7d","photonVoiceAppID":"0b460ea8-065e-49cc-a067-ddaf7b5a2396", "metadataHash": "3225b4ed43082cec01c79acd8b1c09ea335f77870663342a5dededf6f4979f66", "termsAcceptanceNeeded":[],"dailyMissionDateKey":"","dailyMissions":None,"dailyMissionResetTime":0,"serverTimeUnix":1720877961,"gameDataURL":"https://blankzzanimalcompany.pythonanywhere.com/game-data-prod.zip"}'
}

ECON_GAMEPLAY_ITEMS_RESPONSE = {
    'payload': '[{"id":"item_apple","netID":71,"name":"Apple","description":"An apple a day keeps the doctor away!","category":"Consumables","price":200,"value":7,"isLoot":true,"isPurchasable":false,"isUnique":false,"isDevOnly":false},{"id":"item_arrow","netID":103,"name":"Arrow","description":"Can be attached to the crossbow.","category":"Ammo","price":199,"value":8,"isLoot":false,"isPurchasable":true,"isUnique":false,"isDevOnly":false},{"id":"item_arrow_heart","netID":116,"name":"Heart Arrow","description":"A love-themed arrow that will have your targets seeing hearts! ","category":"Ammo","price":199,"value":8,"isLoot":false,"isPurchasable":true,"isUnique":false,"isDevOnly":false}]'
}

SERVER_TIME_RESPONSE = {
    'payload': '{"serverTimeUnix":' + str(int(time.time())) + ',"cachedExpiresAt":' + str(int(time.time()) + 86400) + '}'
}

# Route handlers
@app.route('/v2/account/authenticate/custom', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def authenticate_custom():
    generate_gameplay_loadout()
    return jsonify(generate_tokens() if ENABLE_RANDOM_TOKENS else {
        'token': generate_jwt(generate_unique_user_id()),
        'refresh_token': generate_jwt(generate_unique_user_id())
    })

@app.route('/v2/account/alt2', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
def account_alt2():
    return jsonify(get_default_inventory)

@app.route('/v2/account1', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def account1():
    return jsonify({
        'user': {
            'id': generate_unique_user_id(),
            'username': 'Player',
            'lang_tag': 'en',
            'metadata': '{}',
            'edge_count': 4,
            'create_time': '2024-08-24T07:30:12Z',
            'update_time': '2025-04-05T21:00:27Z'
        },
        'wallet': '{"stashCols": 4, "stashRows": 2, "hardCurrency": 30000000, "softCurrency": 20000000, "researchPoints": 500000}',
        'custom_id': generate_custom_id()
    })

@app.route('/v2/rpc/purchase.avatarItems', methods=['POST'])
def purchase_avatar_items():
    return jsonify({'payload': '{"success": true}'})

@app.route('/v2/rpc/avatar.update', methods=['POST'])
def avatar_update():
    data = request.get_json()
    if data and 'username' in data:
        return jsonify({'payload': f'{{"username": "{data["username"]}", "success": true}}'})
    return jsonify({'payload': '{"success": true}'})

@app.route('/v2/rpc/purchase.gameplayItems', methods=['POST'])
def purchase_gameplay_items():
    return jsonify({'payload': '{"success": true}'})

@app.route('/game-data-prod.zip')
def serve_game_data():
    client_ip = get_client_ip()
    print(f"Request from IP: {client_ip}")

    file_name = 'game-data-prod.zip'
    file_path = os.path.join('/', file_name)

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        # Create a dummy file if it doesn't exist
        try:
            with open(file_path, 'wb') as f:
                f.write(b'dummy game data')
            print(f"Created dummy {file_name}")
        except Exception as e:
            print(f"Failed to create dummy file: {e}")
            return 'File not found', 404

    file_size = os.path.getsize(file_path)
    print(f"Serving {file_name}, size: {file_size} bytes")

    try:
        return send_file(file_path, mimetype='application/zip', as_attachment=False,
                        download_name=file_name, max_age=3600)
    except Exception as e:
        print(f"Error serving file: {e}")
        return f"Error: {str(e)}", 500

@app.route('/v2/account', methods=['GET', 'PUT'])
def account():
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS')
        return response

    if request.method == 'PUT':
        try:
            # Check Content-Type and parse accordingly
            content_type = request.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                data = request.get_json(force=True, silent=True) or {}
            elif 'application/grpc' in content_type or 'application/x-protobuf' in content_type:
                # Handle gRPC/protobuf content
                data = {'grpc_data': 'processed'}  # Placeholder for gRPC data
            else:
                # Try to parse as JSON anyway
                data = request.get_json(force=True, silent=True) or {}

            print(f"Account update received - Content-Type: {content_type}")
            print(f"Update data: {data}")

            # Process the update data
            if data:
                # Handle username updates
                if 'username' in data:
                    print(f"Username update requested: {data['username']}")
                    # You could update the database here

                # Handle avatar updates
                if 'avatar_url' in data:
                    print(f"Avatar update requested: {data['avatar_url']}")

            # Return success response with proper headers
            response = jsonify({
                'success': True,
                'message': 'Account updated successfully'
            })

            # Set proper headers
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Content-Type'] = 'application/json'

            # Add gRPC headers if needed
            if 'application/grpc' in content_type:
                response.headers['Grpc-Metadata-Content-Type'] = 'application/grpc'
                response.headers['Content-Type'] = 'application/json'  # Still return JSON body

            return response

        except Exception as e:
            print(f"Error processing account update: {e}")
            # Return error but still success status to avoid client issues
            response = jsonify({
                'success': False,
                'error': str(e)
            })
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            response.headers['Content-Type'] = 'application/json'
            return response

    # Handle GET request (existing code)
    try:
        ip = get_client_ip()
        user, banned = get_or_create_user(ip)

        if banned or user is None:
            print(f"[ERROR] User banned or None - IP: {ip}, banned: {banned}, user: {user}")
            # Fallback to allow login even if DB fails
            user = {
                'username': 'FallbackPlayer',
                'custom_id': generate_custom_id(),
                'user_id': generate_unique_user_id()
            }

        username = user['username']
        if is_trusted_ip(ip):
            username = 'BLANKZZ [OWNER]'

        account_data = {
            'user': {
                'id': user['user_id'],
                'username': username,
                'lang_tag': 'en',
                'metadata': json.dumps({'isDeveloper': str(is_trusted_ip(ip))}),
                'edge_count': 4,
                'create_time': '2024-08-24T07:30:12Z',
                'update_time': '2025-04-05T21:00:27Z'
            },
            'wallet': '{"stashCols": 16, "stashRows": 8, "hardCurrency": 0, "softCurrency": 99999999999, "researchPoints": 99999}',
            'custom_id': user['custom_id']
        }

        response = jsonify(account_data)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response

    except Exception as e:
        print(f"[FALLBACK] DB failed: {e}")
        import traceback
        traceback.print_exc()
        # Always return valid account data even on error
        fallback_data = {
            'user': {
                'id': generate_unique_user_id(),
                'username': 'FallbackPlayer',
                'lang_tag': 'en',
                'metadata': '{}',
                'edge_count': 4,
                'create_time': '2024-08-24T07:30:12Z',
                'update_time': '2025-04-05T21:00:27Z'
            },
            'wallet': '{"stashCols": 4, "stashRows": 2, "hardCurrency": 30000000, "softCurrency": 20000000, "researchPoints": 500000}',
            'custom_id': generate_custom_id()
        }
        response = jsonify(fallback_data)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        return response

@app.route('/v2/account/link/device', methods=['POST'])
def link_device():
    return jsonify({
        'id': secrets.token_hex(16),
        'user_id': generate_unique_user_id(),
        'linked': True,
        'create_time': '2025-01-15T18:08:45Z'
    })

@app.route('/v2/account/session/refresh', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def refresh_session():
    return jsonify(generate_tokens())

@app.route('/v2/rpc/attest.start', methods=['POST'])
def attest_start():
    return jsonify({
        'payload': json.dumps({
            'status': 'success',
            'attestResult': 'Valid',
            'message': 'Attestation validated'
        })
    })

@app.route('/v2/rpc/mining.balance', methods=['GET'])
def mining_balance():
    response_body = {
        'payload': json.dumps({
            'hardCurrency': 20000000,
            'researchPoints': 999999
        })
    }
    return jsonify(response_body), 200

@app.route('/v2/rpc/purchase.list', methods=['GET'])
def purchase_list():
    response_body = {
        'payload': json.dumps({
            'purchases': [
                {
                    'user_id': generate_unique_user_id(),
                    'product_id': 'RESEARCH_PACK',
                    'transaction_id': '540282689176766',
                    'store': 3,
                    'purchase_time': {'seconds': int(time.time()) - 3600},
                    'create_time': {'seconds': int(time.time()) - 3500, 'nanos': 694669000},
                    'update_time': {'seconds': int(time.time()) - 3500, 'nanos': 694669000},
                    'refund_time': {},
                    'provider_response': json.dumps({'success': True}),
                    'environment': 2
                }
            ]
        })
    }
    return jsonify(response_body), 200

@app.route('/v2/rpc/clientBootstrap', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def client_bootstrap():
    return jsonify(CLIENT_BOOTSTRAP_RESPONSE)

@app.route('/auth', methods=['GET', 'POST'])
def photon_auth():
    auth_token = request.args.get('auth_token')
    print('🔐 Photon Auth Request Received')

    if auth_token:
        print(f"auth_token: {auth_token}")
        message = 'Authentication successful'
    else:
        print('⚠️ No auth_token provided')
        message = 'Authenticated without token'



    fake_user_id = secrets.token_hex(16)
    fake_session_id = secrets.token_hex(12)
    return jsonify({
        'ResultCode': 1,
        'Message': message,
        'UserId': fake_user_id,
        'SessionID': fake_session_id,
        'Authenticated': True
    }), 200

@app.route('/v2/storage', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def storage():
    try:
        # Handle CORS preflight requests
        if request.method == 'OPTIONS':
            response = jsonify({})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', '*')
            response.headers.add('Access-Control-Allow-Methods', '*')
            return response

        # Get client IP and user info
        client_ip = get_client_ip()
        user_info, banned = get_or_create_user(client_ip)

        if banned or not user_info:
            return jsonify({'objects': [], 'error': 'User banned or not found'}), 403

        user_id = user_info.get('user_id', '2e8aace0-282d-4c3d-b9d4-6a3b3ba2c2a6')

        if request.method == 'GET':
            # Handle GET request - return user's storage objects
            collection = request.args.get('collection')
            key = request.args.get('key')
            user_id_param = request.args.get('user_id')

            # If specific user_id is requested, use it (for cross-user access)
            if user_id_param:
                user_id = user_id_param

            objects = get_storage_objects(user_id, collection, key)
            return jsonify({'objects': objects})

        elif request.method == 'POST':
            # Handle POST request - usually for reading multiple objects
            data = request.get_json(force=True, silent=True) or {}

            if 'object_ids' in data:
                # Client wants to read specific objects
                objects = []
                for obj_id in data['object_ids']:
                    collection = obj_id.get('collection')
                    key = obj_id.get('key')
                    obj_user_id = obj_id.get('user_id', user_id)

                    # Get the specific object
                    obj_objects = get_storage_objects(obj_user_id, collection, key)
                    if obj_objects:
                        objects.extend(obj_objects)

                return jsonify({'objects': objects})

            elif 'objects' in data:
                # Client wants to write multiple objects
                write_results = []
                for obj in data['objects']:
                    result = write_storage_object(
                        user_id=obj.get('user_id', user_id),
                        collection=obj.get('collection', ''),
                        key=obj.get('key', ''),
                        value=obj.get('value', ''),
                        version=obj.get('version', ''),
                        permission_read=obj.get('permission_read', 1),
                        permission_write=obj.get('permission_write', 1)
                    )
                    write_results.append(result)

                return jsonify({'objects': write_results})

            else:
                # Default: return user's inventory
                objects = get_user_inventory(user_id)
                return jsonify({'objects': objects})

        elif request.method == 'PUT':
            # Handle PUT request - update storage objects
            data = request.get_json(force=True, silent=True) or {}

            if 'objects' in data:
                write_results = []
                for obj in data['objects']:
                    result = write_storage_object(
                        user_id=obj.get('user_id', user_id),
                        collection=obj.get('collection', ''),
                        key=obj.get('key', ''),
                        value=obj.get('value', ''),
                        version=obj.get('version', ''),
                        permission_read=obj.get('permission_read', 1),
                        permission_write=obj.get('permission_write', 1)
                    )
                    write_results.append(result)

                return jsonify({'objects': write_results})
            else:
                return jsonify({'objects': []})

        elif request.method == 'DELETE':
            # Handle DELETE request - remove storage objects
            data = request.get_json(force=True, silent=True) or {}
            object_ids = data.get('object_ids', [])

            deleted_count = 0
            for obj_id in object_ids:
                if delete_storage_object(
                    user_id=obj_id.get('user_id', user_id),
                    collection=obj_id.get('collection'),
                    key=obj_id.get('key')
                ):
                    deleted_count += 1

            return jsonify({'deleted_count': deleted_count})

        else:
            # Default fallback - return user inventory
            objects = get_user_inventory(user_id)
            return jsonify({'objects': objects})

    except Exception as e:
        print(f"Storage error: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to basic inventory
        user_id = '2e8aace0-282d-4c3d-b9d4-6a3b3ba2c2a6'
        objects = get_user_inventory(user_id)
        return jsonify({'objects': objects})

# Storage helper functions
def get_storage_objects(user_id, collection=None, key=None):
    """Get storage objects for a user with optional filters"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        query = '''
            SELECT collection, key, user_id, value, version, permission_read, permission_write,
                   create_time, update_time
            FROM storage_objects
            WHERE user_id = ?
        '''
        params = [user_id]

        if collection:
            query += ' AND collection = ?'
            params.append(collection)
        if key:
            query += ' AND key = ?'
            params.append(key)

        query += ' ORDER BY collection, key'

        cur.execute(query, params)
        objects = []
        for row in cur.fetchall():
            objects.append({
                'collection': row[0],
                'key': row[1],
                'user_id': row[2],
                'value': row[3],
                'version': row[4],
                'permission_read': row[5],
                'permission_write': row[6],
                'create_time': row[7] or '2024-01-01T00:00:00Z',
                'update_time': row[8] or '2024-01-01T00:00:00Z'
            })

        conn.close()

        # If no objects found in database, return default inventory
        if not objects and not collection and not key:
            return get_default_inventory(user_id)

        return objects

    except Exception as e:
        print(f"Error getting storage objects: {e}")
        return get_default_inventory(user_id)

def write_storage_object(user_id, collection, key, value, version='', permission_read=1, permission_write=1):
    """Write or update a storage object"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # Create storage table if it doesn't exist
        cur.execute('''
            CREATE TABLE IF NOT EXISTS storage_objects (
                collection TEXT,
                key TEXT,
                user_id TEXT,
                value TEXT,
                version TEXT,
                permission_read INTEGER,
                permission_write INTEGER,
                create_time TEXT,
                update_time TEXT,
                PRIMARY KEY (user_id, collection, key)
            )
        ''')

        current_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        # Check if object exists
        cur.execute('''
            SELECT 1 FROM storage_objects
            WHERE user_id = ? AND collection = ? AND key = ?
        ''', (user_id, collection, key))

        if cur.fetchone():
            # Update existing object
            cur.execute('''
                UPDATE storage_objects
                SET value = ?, version = ?, permission_read = ?, permission_write = ?, update_time = ?
                WHERE user_id = ? AND collection = ? AND key = ?
            ''', (value, version, permission_read, permission_write, current_time, user_id, collection, key))
        else:
            # Insert new object
            cur.execute('''
                INSERT INTO storage_objects
                (collection, key, user_id, value, version, permission_read, permission_write, create_time, update_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (collection, key, user_id, value, version, permission_read, permission_write, current_time, current_time))

        conn.commit()
        conn.close()

        return {
            'collection': collection,
            'key': key,
            'user_id': user_id,
            'value': value,
            'version': version,
            'permission_read': permission_read,
            'permission_write': permission_write,
            'create_time': current_time,
            'update_time': current_time
        }

    except Exception as e:
        print(f"Error writing storage object: {e}")
        return {
            'collection': collection,
            'key': key,
            'user_id': user_id,
            'value': value,
            'version': version,
            'permission_read': permission_read,
            'permission_write': permission_write,
            'create_time': '2024-01-01T00:00:00Z',
            'update_time': '2024-01-01T00:00:00Z'
        }

def delete_storage_object(user_id, collection, key):
    """Delete a storage object"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute('''
            DELETE FROM storage_objects
            WHERE user_id = ? AND collection = ? AND key = ?
        ''', (user_id, collection, key))

        conn.commit()
        conn.close()
        return True

    except Exception as e:
        print(f"Error deleting storage object: {e}")
        return False

def get_user_inventory(user_id):
    """Get complete user inventory with gameplay loadout"""
    try:
        # Try to get from database first
        db_objects = get_storage_objects(user_id)
        if db_objects:
            return db_objects

        # Fallback to default inventory
        return get_default_inventory(user_id)

    except Exception as e:
        print(f"Error getting user inventory: {e}")
        return get_default_inventory(user_id)

def get_default_inventory(user_id):
    """Return default inventory structure for a new user"""
    gameplay_loadout = generate_gameplay_loadout()

    return [
        {
            'collection': 'user_avatar',
            'key': '0',
            'user_id': user_id,
            'value': '{"butt": "bp_butt_bigbutt_galaxy", "head": "bp_head_pug", "tail": "bp_tail_goat", "torso": "bp_torso_skeletongorilla", "armLeft": "bp_arm_l_skeletongorilla", "eyeLeft": "bp_eye_kitten", "armRight": "bp_arm_r_skeletongorilla", "eyeRight": "bp_eye_kitten", "accessories": ["acc_fit_varsityjacket", "acc_head_crown"], "primaryColor": "000000"}',
            'version': secrets.token_hex(16),
            'permission_read': 2,
            'create_time': '2024-10-29T00:22:08Z',
            'update_time': '2025-04-04T03:55:19Z'
        },
        {
            'collection': 'user_inventory',
            'key': 'avatar',
            'user_id': user_id,
            'value': '{"items": ["animal_gorilla", "bp_head_gorilla", "bp_eye_gorilla", "bp_torso_gorilla", "bp_arm_l_gorilla", "bp_arm_r_gorilla", "bp_butt_gorilla", "acc_fit_varsityjacket_black", "acc_fit_varsityjacket", "outfit_cube", "acc_fit_cubes", "acc_fit_head_cube", "animal_skeletongorilla"]}',
            'version': secrets.token_hex(16),
            'permission_read': 1,
            'create_time': '2024-10-29T00:22:08Z',
            'update_time': '2025-04-05T06:21:14Z'
        },
        {
            'collection': 'user_inventory',
            'key': 'research',
            'user_id': user_id,
            'value': '{"nodes": ["node_arrow", "node_arrow_heart", "node_arrow_lightbulb", "node_backpack", "node_backpack_large", "node_backpack_large_basketball", "node_backpack_large_clover", "node_balloon", "node_balloon_heart", "node_baseball_bat", "node_boxfan", "node_clapper", "node_cluster_grenade", "node_company_ration", "node_crossbow", "node_crossbow_heart", "node_crowbar", "node_disposable_camera", "node_dynamite", "node_dynamite_cube", "node_flaregun", "node_flashbang", "node_flashlight_mega", "node_football", "node_frying_pan", "node_glowsticks", "node_heart_gun", "node_hookshot", "node_hoverpad", "node_impact_grenade", "node_impulse_grenade", "node_item_nut_shredder", "node_jetpack", "node_lance", "node_mega_broccoli", "node_mini_broccoli", "node_ogre_hands", "node_pickaxe", "node_pickaxe_cny", "node_pickaxe_cube", "node_plunger", "node_pogostick", "node_police_baton", "node_quiver", "node_quiver_heart", "node_revolver", "node_revolver_ammo", "node_rpg", "node_rpg_ammo", "node_rpg_cny", "node_saddle", "node_shield", "node_shield_bones", "node_shield_police", "node_shotgun", "node_shotgun_ammo", "node_skill_backpack_cap_1", "node_skill_backpack_cap_2", "node_skill_backpack_cap_3", "node_skill_explosive_1", "node_skill_gundamage_1", "node_skill_health_1", "node_skill_health_2", "node_skill_left_hip_attachment", "node_skill_melee_1", "node_skill_melee_2", "node_skill_melee_3", "node_skill_right_hip_attachment", "node_skill_selling_1", "node_skill_selling_2", "node_skill_selling_3", "node_stick_armbones", "node_stick_bone", "node_sticker_dispenser", "node_sticky_dynamite", "node_tablet", "node_teleport_grenade", "node_theramin", "node_tripwire_explosive", "node_umbrella", "node_umbrella_clover", "node_whoopie", "node_zipline_gun", "node_zipline_rope"]}',
            'version': secrets.token_hex(16),
            'permission_read': 1,
            'create_time': '2025-02-20T00:51:38Z',
            'update_time': '2025-02-20T01:15:06Z'
        },
        {
            'collection': 'user_inventory',
            'key': 'stash',
            'user_id': user_id,
            'value': '{"items": [{"itemID": "item_backpack_large_base", "colorHue": 202, "colorSaturation": 93, "scaleModifier": -91, "children": []}], "stashPos": 0}',
            'version': secrets.token_hex(16),
            'permission_read': 1,
            'permission_write': 1,
            'create_time': '2025-02-20T00:51:38Z',
            'update_time': '2025-04-05T10:03:13Z'
        },
        {
            'collection': 'user_inventory',
            'key': 'gameplay_loadout',
            'user_id': user_id,
            'value': gameplay_loadout['objects'][0]['value'],
            'version': secrets.token_hex(16),
            'permission_read': 1,
            'permission_write': 1,
            'create_time': '2025-02-20T00:51:50Z',
            'update_time': '2025-04-05T21:06:17Z'
        },
        {
            'collection': 'user_preferences',
            'key': 'gameplay_items',
            'user_id': user_id,
            'value': '{"recents": ["item_backpack_small_base", "item_flaregun", "item_tele_grenade", "item_glowstick", "item_jetpack", "item_stick_bone", "item_dynamite_cube", "item_tablet", "item_plunger", "item_flashlight_mega"], "favorites": ["item_flaregun"]}',
            'version': secrets.token_hex(16),
            'permission_read': 1,
            'permission_write': 1,
            'create_time': '2025-02-20T00:52:27Z',
            'update_time': '2025-04-05T21:04:05Z'
        }
    ]

@app.route('/v2/storage/econ_gameplay_items', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
def econ_gameplay_items():
    return jsonify(ECON_GAMEPLAY_ITEMS_RESPONSE)

@app.route("/v2/friends", methods=["GET", "POST"])
def friends():
    return jsonify({
  "friends": [
    {
      "user": {
        "id": "8c1acc32f2454fb9a9a76fb6dfbf572f",
        "username": "BLANKZZ [OWNER]",
        "display_name": "BLANKZZ [OWNER]",
        "lang_tag": "en",
        "metadata": "{\"IsDeveloper\": true}",
        "create_time": "2024-10-19T10:33:56Z",
        "update_time": "2025-07-23T17:58:40Z"
      },
      "state": 1,
      "update_time": "2025-02-20T13:46:53Z",
      "metadata": "{\"IsDeveloper\": true}"
    }
  ],
  "cursor": "M_-DAwEBDmVkZ2VMaXN0Q3Vyc29yAf-EAAECAQVTdGF0ZQEEAAEIUG9zaXRpb24BBAAAAA3_hAL4MIT4gPadsnQA"
})


@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def index():
    return "Server is running successfully!"

# Add these routes to your Flask app

@app.route('/admin')
def admin():
    html_string = """
        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Database Admin Panel</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid transparent;
            border-bottom: none;
            margin-right: 5px;
            border-radius: 5px 5px 0 0;
        }
        .tab.active {
            background: #007bff;
            color: white;
            border-color: #007bff;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, select, textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }
        button:hover {
            background: #0056b3;
        }
        button.danger {
            background: #dc3545;
        }
        button.danger:hover {
            background: #c82333;
        }
        .alert {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .alert.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .alert.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .search-box {
            margin-bottom: 20px;
        }
        .actions {
            display: flex;
            gap: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Database Admin Panel</h1>

        <div class="tabs">
            <div class="tab active" onclick="switchTab('users')">Users</div>
            <div class="tab" onclick="switchTab('banned')">Banned IPs</div>
            <div class="tab" onclick="switchTab('add')">Add User</div>
            <div class="tab" onclick="switchTab('stats')">Statistics</div>
        </div>

        <!-- Users Tab -->
        <div id="users" class="tab-content active">
            <h2>User Management</h2>
            <div class="search-box">
                <input type="text" id="searchUsers" placeholder="Search users..." onkeyup="searchTable('usersTable', this.value)">
            </div>
            <div id="usersTableContainer">
                <table id="usersTable">
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Username</th>
                            <th>Custom ID</th>
                            <th>Create Time</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="usersTableBody">
                        <!-- Users will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Banned IPs Tab -->
        <div id="banned" class="tab-content">
            <h2>Banned IP Management</h2>
            <div class="form-group">
                <label for="banIp">Ban IP Address:</label>
                <input type="text" id="banIp" placeholder="Enter IP address">
                <button onclick="banIp()">Ban IP</button>
            </div>
            <table id="bannedTable">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="bannedTableBody">
                    <!-- Banned IPs will be loaded here -->
                </tbody>
            </table>
        </div>

        <!-- Add User Tab -->
        <div id="add" class="tab-content">
            <h2>Add New User</h2>
            <form id="addUserForm">
                <div class="form-group">
                    <label for="ip">IP Address:</label>
                    <input type="text" id="ip" required>
                </div>
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" required>
                </div>
                <div class="form-group">
                    <label for="custom_id">Custom ID:</label>
                    <input type="text" id="custom_id" required>
                </div>
                <button type="submit">Add User</button>
                <button type="button" onclick="generateRandomUser()">Generate Random User</button>
            </form>
        </div>

        <!-- Statistics Tab -->
        <div id="stats" class="tab-content">
            <h2>Database Statistics</h2>
            <div id="statsContent">
                <!-- Statistics will be loaded here -->
            </div>
        </div>

        <div id="alert" class="alert" style="display: none;"></div>
    </div>

    <script>
        let currentEditingRow = null;

        // Switch between tabs
        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            document.querySelector(`.tab[onclick="switchTab('${tabName}')"]`).classList.add('active');
            document.getElementById(tabName).classList.add('active');

            if (tabName === 'users') loadUsers();
            if (tabName === 'banned') loadBannedIps();
            if (tabName === 'stats') loadStats();
        }

        // Load users from database
        async function loadUsers() {
            try {
                const response = await fetch('/admin/users');
                const users = await response.json();

                const tbody = document.getElementById('usersTableBody');
                tbody.innerHTML = '';

                users.forEach(user => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${user.ip}</td>
                        <td><span class="editable" data-field="username" data-ip="${user.ip}">${user.username}</span></td>
                        <td><span class="editable" data-field="custom_id" data-ip="${user.ip}">${user.custom_id}</span></td>
                        <td>${new Date(user.create_time * 1000).toLocaleString()}</td>
                        <td class="actions">
                            <button onclick="editUser('${user.ip}')">Edit</button>
                            <button class="danger" onclick="deleteUser('${user.ip}')">Delete</button>
                            <button class="danger" onclick="banUser('${user.ip}')">Ban</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });

                // Make fields editable
                document.querySelectorAll('.editable').forEach(element => {
                    element.addEventListener('click', makeEditable);
                });

            } catch (error) {
                showAlert('Error loading users: ' + error.message, 'error');
            }
        }

        // Load banned IPs
        async function loadBannedIps() {
            try {
                const response = await fetch('/admin/banned');
                const bannedIps = await response.json();

                const tbody = document.getElementById('bannedTableBody');
                tbody.innerHTML = '';

                bannedIps.forEach(ip => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${ip.ip}</td>
                        <td>
                            <button class="danger" onclick="unbanIp('${ip.ip}')">Unban</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                showAlert('Error loading banned IPs: ' + error.message, 'error');
            }
        }

        // Load statistics
        async function loadStats() {
            try {
                const response = await fetch('/admin/stats');
                const stats = await response.json();

                document.getElementById('statsContent').innerHTML = `
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                        <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; text-align: center;">
                            <h3>Total Users</h3>
                            <p style="font-size: 2em; margin: 0;">${stats.total_users}</p>
                        </div>
                        <div style="background: #fff3cd; padding: 20px; border-radius: 8px; text-align: center;">
                            <h3>Banned IPs</h3>
                            <p style="font-size: 2em; margin: 0;">${stats.banned_ips}</p>
                        </div>
                        <div style="background: #d1ecf1; padding: 20px; border-radius: 8px; text-align: center;">
                            <h3>Oldest User</h3>
                            <p style="margin: 0;">${stats.oldest_user ? new Date(stats.oldest_user * 1000).toLocaleDateString() : 'N/A'}</p>
                        </div>
                        <div style="background: #d4edda; padding: 20px; border-radius: 8px; text-align: center;">
                            <h3>Newest User</h3>
                            <p style="margin: 0;">${stats.newest_user ? new Date(stats.newest_user * 1000).toLocaleDateString() : 'N/A'}</p>
                        </div>
                    </div>
                `;
            } catch (error) {
                showAlert('Error loading statistics: ' + error.message, 'error');
            }
        }

        // Make field editable
        function makeEditable(event) {
            const element = event.target;
            const currentValue = element.textContent;
            const field = element.dataset.field;
            const ip = element.dataset.ip;

            element.innerHTML = `
                <input type="text" value="${currentValue}"
                       onblur="saveField('${ip}', '${field}', this.value)"
                       onkeypress="if(event.key==='Enter') this.blur()"
                       style="width: 100%; padding: 2px;" autofocus>
            `;
            element.querySelector('input').focus();
        }

        // Save field value
        async function saveField(ip, field, value) {
            try {
                const response = await fetch('/admin/update-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        ip: ip,
                        field: field,
                        value: value
                    })
                });

                const result = await response.json();
                if (result.success) {
                    showAlert('User updated successfully!', 'success');
                    loadUsers();
                } else {
                    showAlert('Error updating user: ' + result.error, 'error');
                }
            } catch (error) {
                showAlert('Error updating user: ' + error.message, 'error');
            }
        }

        // Add new user
        document.getElementById('addUserForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const formData = {
                ip: document.getElementById('ip').value,
                username: document.getElementById('username').value,
                custom_id: document.getElementById('custom_id').value
            };

            try {
                const response = await fetch('/admin/add-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();
                if (result.success) {
                    showAlert('User added successfully!', 'success');
                    document.getElementById('addUserForm').reset();
                    switchTab('users');
                } else {
                    showAlert('Error adding user: ' + result.error, 'error');
                }
            } catch (error) {
                showAlert('Error adding user: ' + error.message, 'error');
            }
        });

        // Generate random user
        function generateRandomUser() {
            document.getElementById('ip').value = `192.168.1.${Math.floor(Math.random() * 255)}`;
            document.getElementById('username').value = `User${Math.floor(Math.random() * 1000)}`;
            document.getElementById('custom_id').value = Math.random().toString().substr(2, 17);
        }

        // Ban IP
        async function banIp() {
            const ip = document.getElementById('banIp').value;
            if (!ip) {
                showAlert('Please enter an IP address', 'error');
                return;
            }

            try {
                const response = await fetch('/admin/ban-ip', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ ip: ip })
                });

                const result = await response.json();
                if (result.success) {
                    showAlert('IP banned successfully!', 'success');
                    document.getElementById('banIp').value = '';
                    loadBannedIps();
                } else {
                    showAlert('Error banning IP: ' + result.error, 'error');
                }
            } catch (error) {
                showAlert('Error banning IP: ' + error.message, 'error');
            }
        }

        // Ban user
        async function banUser(ip) {
            if (confirm(`Are you sure you want to ban IP ${ip}?`)) {
                try {
                    const response = await fetch('/admin/ban-ip', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ ip: ip })
                    });

                    const result = await response.json();
                    if (result.success) {
                        showAlert('User banned successfully!', 'success');
                        loadUsers();
                    } else {
                        showAlert('Error banning user: ' + result.error, 'error');
                    }
                } catch (error) {
                    showAlert('Error banning user: ' + error.message, 'error');
                }
            }
        }

        // Unban IP
        async function unbanIp(ip) {
            if (confirm(`Are you sure you want to unban IP ${ip}?`)) {
                try {
                    const response = await fetch('/admin/unban-ip', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ ip: ip })
                    });

                    const result = await response.json();
                    if (result.success) {
                        showAlert('IP unbanned successfully!', 'success');
                        loadBannedIps();
                    } else {
                        showAlert('Error unbanning IP: ' + result.error, 'error');
                    }
                } catch (error) {
                    showAlert('Error unbanning IP: ' + error.message, 'error');
                }
            }
        }

        // Delete user
        async function deleteUser(ip) {
            if (confirm(`Are you sure you want to delete user with IP ${ip}?`)) {
                try {
                    const response = await fetch('/admin/delete-user', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ ip: ip })
                    });

                    const result = await response.json();
                    if (result.success) {
                        showAlert('User deleted successfully!', 'success');
                        loadUsers();
                    } else {
                        showAlert('Error deleting user: ' + result.error, 'error');
                    }
                } catch (error) {
                    showAlert('Error deleting user: ' + error.message, 'error');
                }
            }
        }

        // Search table
        function searchTable(tableId, query) {
            const table = document.getElementById(tableId);
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;

                for (let j = 0; j < cells.length; j++) {
                    const cell = cells[j];
                    if (cell.textContent.toLowerCase().includes(query.toLowerCase())) {
                        found = true;
                        break;
                    }
                }

                rows[i].style.display = found ? '' : 'none';
            }
        }

        // Show alert message
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.textContent = message;
            alert.className = `alert ${type}`;
            alert.style.display = 'block';

            setTimeout(() => {
                alert.style.display = 'none';
            }, 5000);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadUsers();
        });
    </script>
</body>
</html>
        """
    return render_template_string(html_string)

@app.route('/admin/users')
def get_users():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT ip, username, custom_id, create_time FROM users ORDER BY create_time DESC')
        users = []
        for row in cur.fetchall():
            users.append({
                'ip': row[0],
                'username': row[1],
                'custom_id': row[2],
                'create_time': row[3]
            })
        conn.close()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/banned')
def get_banned_ips():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT ip FROM banned_ips')
        banned_ips = [{'ip': row[0]} for row in cur.fetchall()]
        conn.close()
        return jsonify(banned_ips)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats')
def get_stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        # Total users
        cur.execute('SELECT COUNT(*) FROM users')
        total_users = cur.fetchone()[0]

        # Banned IPs
        cur.execute('SELECT COUNT(*) FROM banned_ips')
        banned_ips = cur.fetchone()[0]

        # Oldest user
        cur.execute('SELECT MIN(create_time) FROM users')
        oldest_user = cur.fetchone()[0]

        # Newest user
        cur.execute('SELECT MAX(create_time) FROM users')
        newest_user = cur.fetchone()[0]

        conn.close()

        return jsonify({
            'total_users': total_users,
            'banned_ips': banned_ips,
            'oldest_user': oldest_user,
            'newest_user': newest_user
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/update-user', methods=['POST'])
def update_user():
    try:
        data = request.get_json()
        ip = data['ip']
        field = data['field']
        value = data['value']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(f'UPDATE users SET {field} = ? WHERE ip = ?', (value, ip))
        conn.commit()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/add-user', methods=['POST'])
def add_user():
    try:
        data = request.get_json()
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO users (ip, username, custom_id, create_time) VALUES (?, ?, ?, ?)',
                   (data['ip'], data['username'], data['custom_id'], time.time()))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/ban-ip', methods=['POST'])
def ban_ip():
    try:
        data = request.get_json()
        ip = data['ip']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)', (ip,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/unban-ip', methods=['POST'])
def unban_ip():
    try:
        data = request.get_json()
        ip = data['ip']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('DELETE FROM banned_ips WHERE ip = ?', (ip,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    try:
        data = request.get_json()
        ip = data['ip']

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE ip = ?', (ip,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@sockets.route("/ws")
def ws_route(ws):
    while not ws.closed:
        msg = ws.receive()
        if msg:
            ws.send(json.dumps({
                "cid": "29",
                "status_update": {
                    "status": json.dumps({
                        "roomCode": "",
                        "gameMode": 0,
                        "appearOffline": False,
                        "clientVersion": "1.17.1.1147_c6aabe18",
                        "photonVersion": "UkqqufU7dTP1FgbMqS39"
                    })
                }
            }))

if __name__ == '__main__':
    print("Starting Gorilla Tag Server Emulator...")
    print("Make sure game-data-prod.zip exists in the mysite directory")
    app.run(debug=False, host='0.0.0.0', port=5000)
