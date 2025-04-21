from flask import Flask, render_template, request, redirect, url_for, jsonify, session, send_file, flash, make_response, abort, Response, send_from_directory
import requests
import json
import os
import sqlite3
from datetime import datetime
import time
import threading
import string
import random
from contextlib import closing
import psutil
from flask_cors import cross_origin
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = '0d23caaa3479b02511e1af24744'  # Needed for session handling

TMDB_API_KEY = '0d23caaa3479b02511e1af2047fb4744'
BASE_URL = 'https://api.themoviedb.org/3'

DATABASE = 'data.db'
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"
CLIENT_ID = '59790544-ca0c-4b77-b338-26ff9d1b676f'
TENANT_ID = '0fd666e8-0b3d-41ea-a5ef-1c509130bd94'
DEVICE_CODE_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode'
TOKEN_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token'
SCOPES = "openid profile email offline_access https://graph.microsoft.com/.default"
# Predefined password and username for your API
MY_PASSWORD = 'mypassword'
MY_USERNAME = 'main-sever'
BASE_API_URL = "https://severv1.onrender.com"
GP_API_KEY = "96dc76c9be123d120f32a9b624c7682c14dae03e"
KEY_API_URL = "https://severv1.onrender.com/mypassword/main_sever1/free/"
TEMP_PAGES_FILE = "temp_pages.json"
temp_pages_lock = threading.Lock()
proxy_lock = threading.Lock()
PROXY_MAPPING_FILE = 'proxy_mappings.json'
PROXY_STATUS_FILE = 'proxy_status.json'
PERFORMANCE_METER_FILE = 'performance_meter.json'

last_net_io = None
last_net_time = None
# Add to constants section

@app.route('/.well-known/discord')
def serve_discord_verification():
    return send_from_directory('.well-known', 'discord')

@app.route('/api/top5', methods=['GET'])
@cross_origin()
def api_top5():
    try:
        # Query the 5 most recently added shows
        shows = query_db("""
            SELECT imdb_id, name, thumbnail, year, rating, description, type, quality
            FROM shows 
            ORDER BY date_added DESC 
            LIMIT 5
        """)
        
        # Convert to list of dictionaries and format
        result = []
        for show in shows:
            result.append({
                "imdb_id": show['imdb_id'],
                "title": show['name'],
                "thumbnail": show['thumbnail'],
                "year": show['year'],
                "rating": show['rating'],
                "description": show['description'],
                "type": show['type'],
                "quality": show['quality']
            })
            
        return jsonify(result)
    
    except Exception as e:
        app.logger.error(f"Error in /api/top5: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    if 'admin_logged_in' not in session:
        return jsonify({"message": "Unauthorized"}), 403

    try:
        access_token = get_valid_token()
        headers = {"Authorization": f"Bearer {access_token}"}

        # Define the folder ID where you want to store the backup
        folder_id = "01ZDEC6CXCKCNDJGM7X5EK33GFMY6DW5TL"

        # Upload the file
        file_path = "data.db"
        file_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        upload_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_id}:/{file_name}:/content"

        with open(file_path, "rb") as file_data:
            response = requests.put(upload_url, headers=headers, data=file_data)

        if response.status_code in [200, 201]:
            return jsonify({"message": "Backup uploaded successfully!"})
        else:
            return jsonify({"message": "Failed to upload backup", "error": response.text}), response.status_code

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500
# Add routes
@app.route('/toggle_performance_meter', methods=['POST'])
def toggle_performance_meter():
    if 'admin_logged_in' not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    try:
        if not os.path.exists(PERFORMANCE_METER_FILE):
            with open(PERFORMANCE_METER_FILE, 'w') as f:
                json.dump({"enabled": False}, f)
                
        with open(PERFORMANCE_METER_FILE, 'r+') as f:
            data = json.load(f)
            new_status = not data.get('enabled', False)
            data['enabled'] = new_status
            f.seek(0)
            json.dump(data, f)
            f.truncate()
            
        return jsonify({
            "message": f"Performance meter {'enabled' if new_status else 'disabled'}",
            "enabled": new_status
        }), 200
        
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/performance_meter_status', methods=['GET'])
def performance_meter_status():
    try:
        if not os.path.exists(PERFORMANCE_METER_FILE):
            return jsonify({"enabled": False})
            
        with open(PERFORMANCE_METER_FILE, 'r') as f:
            data = json.load(f)
            return jsonify({"enabled": data.get('enabled', False)})
    except:
        return jsonify({"enabled": False})
        
@app.route('/performance_metrics')
def performance_metrics():
    # Check admin authentication
    if 'admin_logged_in' not in session:
        return jsonify({"error": "Unauthorized access"}), 403
    
    global last_net_io, last_net_time
    
    # Get CPU and Memory usage
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    
    # Calculate network usage
    net_io = psutil.net_io_counters()
    current_time = datetime.now()
    network_stats = {'upload': 0.0, 'download': 0.0}
    
    if last_net_io and last_net_time:
        time_diff = (current_time - last_net_time).total_seconds()
        if time_diff > 0:
            upload = (net_io.bytes_sent - last_net_io.bytes_sent) / (1024 * 1024) / time_diff
            download = (net_io.bytes_recv - last_net_io.bytes_recv) / (1024 * 1024) / time_diff
            network_stats = {
                'upload': max(0.0, upload),
                'download': max(0.0, download)
            }
    
    last_net_io = net_io
    last_net_time = current_time

    return jsonify({
        'cpu': cpu_usage,
        'memory': memory_usage,
        'network': network_stats,
        'timestamp': datetime.now().isoformat()
    })
    
def init_db():
    with closing(sqlite3.connect(DATABASE)) as conn:
        cursor = conn.cursor()
        # Create main tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                imdb_id TEXT UNIQUE,
                type TEXT,
                name TEXT,
                thumbnail TEXT,
                rating REAL,
                description TEXT,
                year INTEGER,
                trailer TEXT,
                file_id TEXT,
                quality TEXT,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS genres (
                show_id INTEGER,
                genre TEXT,
                FOREIGN KEY(show_id) REFERENCES shows(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS seasons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                show_id INTEGER,
                season_number INTEGER,
                episode_count INTEGER,
                FOREIGN KEY(show_id) REFERENCES shows(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS episodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                season_id INTEGER,
                episode_number INTEGER,
                name TEXT,
                description TEXT,
                thumbnail TEXT,
                air_date TEXT,
                file_id TEXT,
                rating REAL,
                FOREIGN KEY(season_id) REFERENCES seasons(id)
            )
        ''')
        # Proxy system tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS proxy_mappings (
                file_id TEXT PRIMARY KEY,
                proxy_id TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS proxy_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled BOOLEAN NOT NULL DEFAULT FALSE
            )
        ''')
        cursor.execute('INSERT OR IGNORE INTO proxy_status (id, enabled) VALUES (1, FALSE)')

        # Requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                year TEXT,
                media_type TEXT,
                email TEXT,
                status TEXT DEFAULT 'pending'
            )
        ''')

        conn.commit()

init_db()
# Add these helper functions
def get_db():
    return sqlite3.connect(DATABASE)

def query_db(query, args=(), one=False):
    with closing(get_db()) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, args)
        rv = [dict(row) for row in cursor.fetchall()]
        return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    with closing(get_db()) as conn:
        cursor = conn.cursor()
        cursor.execute(query, args)
        conn.commit()
        return cursor.lastrowid

# Proxy system functions
def load_proxy_mappings():
    with proxy_lock:
        rows = query_db("SELECT file_id, proxy_id FROM proxy_mappings")
        return {row['file_id']: row['proxy_id'] for row in rows}

def save_proxy_mappings(mappings):
    with proxy_lock:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM proxy_mappings")
        if mappings:
            data = [(file_id, proxy_id) for file_id, proxy_id in mappings.items()]
            cursor.executemany("INSERT INTO proxy_mappings (file_id, proxy_id) VALUES (?, ?)", data)
        conn.commit()
        conn.close()

def get_proxy_status():
    row = query_db("SELECT enabled FROM proxy_status WHERE id = 1", one=True)
    return bool(row['enabled']) if row else False

# Proxy routes
@app.route('/toggle_proxy', methods=['POST'])
def toggle_proxy():
    if 'admin_logged_in' not in session:
        return jsonify({"message": "Unauthorized"}), 403
    
    new_status = not get_proxy_status()
    insert_db("UPDATE proxy_status SET enabled = ? WHERE id = 1", (new_status,))
    
    return jsonify({
        "message": f"Proxy {'enabled' if new_status else 'disabled'}",
        "enabled": new_status
    })

@app.route('/proxy_status', methods=['GET'])
def proxy_status():
    return jsonify({"enabled": get_proxy_status()})

@app.route('/download/<proxy_id>')
def proxy_download(proxy_id):
    proxy_mappings = load_proxy_mappings()
    file_id = next((k for k, v in proxy_mappings.items() if v == proxy_id), None)
    
    if not file_id:
        abort(404)
    
    # Determine which token to use
    if file_id.startswith("MARIO"):
        actual_file_id = file_id[5:]
        token_file = 'user_token2.json'
    else:
        actual_file_id = file_id
        token_file = 'user_token.json'
    
    # Get actual OneDrive link with download parameter
    direct_url = get_onedrive_business_link(actual_file_id, token_file)
    if not direct_url:
        abort(404)
    
    # Add download parameter if not present
    if "?download=1" not in direct_url:
        direct_url += "?download=1"
    
    # Stream the file
    range_header = request.headers.get('Range', '')
    headers = {'Range': range_header} if range_header else {}
    
    response = requests.get(direct_url, headers=headers, stream=True)
    
    # Create response with modified headers
    resp_headers = dict(response.headers)
    
    # Force download behavior
    filename = "video"  # You can extract from Content-Disposition if available
    content_disp = resp_headers.get('Content-Disposition', '')
    if 'filename=' in content_disp:
        filename = content_disp.split('filename=')[1].strip('"')
    
    resp_headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return Response(
        response.iter_content(chunk_size=8192),
        status=response.status_code,
        content_type=response.headers.get('Content-Type', 'application/octet-stream'),
        headers=resp_headers
    )

def get_db():
    return sqlite3.connect(DATABASE)

def query_db(query, args=(), one=False):
    with closing(get_db()) as conn:
        cursor = conn.cursor()
        cursor.execute(query, args)
        rv = [dict((cursor.description[idx][0], value) for idx, value in enumerate(row)) for row in cursor.fetchall()]
        return (rv[0] if rv else None) if one else rv

def insert_db(query, args=()):
    with closing(get_db()) as conn:
        cursor = conn.cursor()
        cursor.execute(query, args)
        conn.commit()
        return cursor.lastrowid

def login_required(func):
    def wrapper(*args, **kwargs):
        api_key = request.cookies.get('apiKey')
        if not api_key:
            return redirect(url_for('index'))  # No key at all

        is_valid, error_message = validate_api_key(api_key)
        if not is_valid:
            response = make_response(redirect(url_for('index')))
            response.delete_cookie('apiKey')  # Remove expired key
            return response  # Redirect to login
        
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper

def login_required(func):
    def wrapper(*args, **kwargs):
        api_key = request.cookies.get('apiKey')
        if not api_key:
            return redirect(url_for('index'))  # No key at all

        is_valid, error_message = validate_api_key(api_key)
        if not is_valid:
            response = make_response(redirect(url_for('index')))
            response.delete_cookie('apiKey')  # Remove expired key
            return response  # Redirect to login
        
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper

@app.route('/get_file_metadata/<file_id>', methods=['GET'])
@login_required
def get_file_metadata(file_id):
    try:
        # Determine which token file to use
        if file_id.startswith("MARIO"):
            actual_file_id = file_id[5:]  # Remove "MARIO" prefix
            token_file = 'user_token2.json'
        else:
            actual_file_id = file_id
            token_file = 'user_token.json'

        # Get a valid access token
        access_token = get_valid_token(token_file)

        # Fetch file metadata from Microsoft Graph API
        url = f"https://graph.microsoft.com/v1.0/me/drive/items/{actual_file_id}"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            metadata = response.json()
            file_size = metadata.get('size', 0)
            return jsonify({"file_size": file_size, "source": token_file}), 200
        else:
            return jsonify({"error": "Failed to fetch file metadata"}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/toggle_lockdown', methods=['POST'])
def toggle_lockdown():
    if 'admin_logged_in' not in session:
        return jsonify({"message": "Unauthorized access"}), 403

    with open('lockdown.json', 'r') as f:
        lockdown_data = json.load(f)

    # Toggle the state
    lockdown_data['lockdown'] = 'off' if lockdown_data['lockdown'] == 'on' else 'on'

    # Save the updated state
    with open('lockdown.json', 'w') as f:
        json.dump(lockdown_data, f, indent=4)

    return jsonify({"message": "Lockdown state updated", "lockdown": lockdown_data['lockdown']})
    
@app.route('/lockdown_status', methods=['GET'])
def lockdown_status():
    with open('lockdown.json', 'r') as f:
        lockdown_data = json.load(f)
    return jsonify({"lockdown": lockdown_data['lockdown']})
    
@app.route('/lockdown')
def lockdown():
    # Check the current lockdown state
    with open('lockdown.json', 'r') as f:
        lockdown_data = json.load(f)

    # If lockdown is off, redirect to home page
    if lockdown_data.get("lockdown") == "off":
        return redirect(url_for('index'))

    # Render the lockdown page if lockdown is on
    return render_template('lockdown.html')
   
@app.before_request
def check_lockdown():
    # Skip lockdown for specific routes
    if request.path in ['/toggle_lockdown', '/lockdown', '/admin', '/admin/home', '/lockdown_status', '/freemode_status', '/toggle_freemode', '/get_storage_info']:
        return

    # Read lockdown status
    with open('lockdown.json', 'r') as f:
        lockdown_data = json.load(f)

    if lockdown_data.get("lockdown") == "on":
        return redirect(url_for('lockdown'))


@app.route('/warning')
def warning():
    return render_template('warning.html')

@app.route('/upload_name', methods=['POST'])
def upload_name():
    if 'admin_logged_in' in session:
        # Check if the uploaded file is present
        if 'name_file' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('home'))
        
        file = request.files['name_file']

        # Ensure the uploaded file is named 'name.json'
        if file.filename != 'name.json':
            flash("Please upload a file named name.json", "error")
            return redirect(url_for('home'))

        # Define the path to save name.json
        file_path = os.path.join(app.root_path, 'name.json')

        # If name.json already exists, remove it
        if os.path.exists(file_path):
            os.remove(file_path)

        # Save the new file
        file.save(file_path)
        flash("name.json uploaded successfully", "success")
        
        return redirect(url_for('home'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/suggestions', methods=['GET'])
def suggestions():
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])

    # Use DISTINCT to eliminate duplicate names
    results = query_db("""
        SELECT DISTINCT name FROM shows 
        WHERE LOWER(name) LIKE ?
        LIMIT 5
    """, (f"%{query}%",))

    return jsonify([result['name'] for result in results])

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Route to validate the API key and save it in a cookie
def validate_api_key(api_key):
    """Validate API key format first, then check with external API."""
    
    # List of valid prefixes
    valid_prefixes = [
        "CUSTOMxJAIxMARIOx",
        "1MONTHxJAIxMARIOx",
        "7DAYxJAIxMARIOx",
        "1DAYxJAIxMARIOx",
        "FREExJAIxMARIOx",
        "1HOURxJAIxMARIOx"
    ]

    # Check if the key starts with a valid prefix
    if not any(api_key.startswith(prefix) for prefix in valid_prefixes):
        return False, "KEY IS INVALID"

    # Proceed with external API validation
    user_ip = request.remote_addr
    if request.headers.get('X-Forwarded-For'):
        user_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    
    api_url = f"{BASE_API_URL}/{MY_PASSWORD}/{MY_USERNAME}/check/{api_key}/{user_ip}"
    
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            return True, None  # Key is valid
        else:
            return False, response.json().get('message', 'Unknown error')
    except requests.RequestException:
        return False, "VALIDATION SERVICE UNAVAILABLE"

@app.route('/validate-key', methods=['POST'])
def validate_key():
    data = request.json
    user_api_key = data.get('apiKey')

    if not user_api_key:
        return jsonify({'message': 'API key is required'}), 400

    is_valid, error_message = validate_api_key(user_api_key)
    if is_valid:
        response = make_response(jsonify({'message': 'ACCESS GRANTED!'}), 200)
        response.set_cookie('apiKey', user_api_key, max_age=60*60*24*30)
        return response
    else:
        # Use the error message from API
        return jsonify({'message': error_message or 'Key validation failed'}), 401


@app.route('/get_storage_info', methods=['GET'])
def get_storage_info():
    try:
        # Read lockdown status
        with open('lockdown.json', 'r') as f:
            lockdown_data = json.load(f)

        lockdown_active = lockdown_data.get("lockdown") == "on"

        # If lockdown is active and user is not admin, redirect to /lockdown
        if lockdown_active and 'admin_logged_in' not in session:
            return redirect(url_for('lockdown'))

        # If lockdown is not active and user is not admin, show 404 page
        if 'admin_logged_in' not in session:
            return render_template('404.html'), 404

        # Proceed to fetch storage info for admins
        server = request.args.get('server', '1')
        token_file = 'user_token.json' if server == '1' else 'user_token2.json'
        access_token = get_valid_token(token_file)
        headers = {"Authorization": f"Bearer {access_token}"}
        url = "https://graph.microsoft.com/v1.0/me/drive"

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                "used_bytes": data['quota']['used'],
                "total_bytes": data['quota']['total']
            })
        else:
            return render_template('error.html', error="Failed to fetch storage data"), response.status_code

    except Exception as e:
        return render_template('error.html', error=str(e)), 500
        
@app.route('/replace_backup', methods=['POST'])
def replace_backup():
    try:
        access_token = get_valid_token()  # Ensure you have a valid access token
        headers = {"Authorization": f"Bearer {access_token}"}
        folder_id = "01ZDEC6CXCKCNDJGM7X5EK33GFMY6DW5TL"

        # Step 1: Get the list of files in the backup folder
        response = requests.get(f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_id}/children", headers=headers)
        if response.status_code != 200:
            print("Error: Failed to retrieve backup files", response.status_code, response.text)
            return jsonify({"message": "Failed to retrieve backup files."}), 500
        
        files = response.json().get('value', [])
        if not files:
            print("Error: No files found in the backup folder.")
            return jsonify({"message": "No files found in the backup folder."}), 404

        # Step 2: Sort files by last modified date, select the latest
        files = sorted(files, key=lambda x: x['lastModifiedDateTime'], reverse=True)
        latest_file = files[0]
        file_id = latest_file['id']
        print(f"Latest file ID: {file_id}, Name: {latest_file['name']}")

        # Step 3: Delete old data.db if it exists
        if os.path.exists('data.db'):
            os.remove('data.db')

        # Step 4: Download the latest backup file
        download_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/content"
        download_response = requests.get(download_url, headers=headers)
        if download_response.status_code == 200:
            with open('data.db', 'wb') as f:
                f.write(download_response.content)
            print("Backup successfully replaced with the latest version.")
            return jsonify({"message": "Backup successfully replaced with latest version."})
        else:
            print("Error: Failed to download the latest backup.", download_response.status_code, download_response.text)
            return jsonify({"message": "Failed to download the latest backup."}), 500
    except Exception as e:
        print("Exception occurred:", e)
        return jsonify({"message": "An error occurred during the replacement process."}), 500


@app.route('/update_temp', methods=['POST'])
def update_temp():
    if 'admin_logged_in' in session:
        # Load temp.json data
        with open('temp.json', 'r') as f:
            data = json.load(f)
        
        # Update basic data
        data['thumbnail'] = request.form['thumbnail']
        data['name'] = request.form['name']
        data['rating'] = request.form['rating']
        data['description'] = request.form['description']
        data['year'] = request.form['year']
        data['genres'] = request.form.getlist('genres')
        
        # Store selected quality separately and update IMDb ID
        selected_quality = request.form.get('quality')
        data['quality'] = selected_quality
        data['imdb_id'] = f"{data['imdb_id'].split('-')[0]}-{selected_quality}"  # Append quality to IMDb ID

        # Update episode details if type is TV
        if data['type'] == 'tv':
            for season in data['seasons']:
                for i, episode in enumerate(season['episodes']):
                    # Update episode name
                    episode_name = request.form.get(f'episode_name_{season["season_number"]}_{i}')
                    if episode_name:
                        episode['name'] = episode_name
                    
                    # Update episode thumbnail
                    episode_thumbnail = request.form.get(f'episode_thumbnail_{season["season_number"]}_{i}')
                    if episode_thumbnail:
                        episode['thumbnail'] = episode_thumbnail
                    
                    # Update episode description
                    episode_description = request.form.get(f'episode_description_{season["season_number"]}_{i}')
                    if episode_description:
                        episode['description'] = episode_description
                    
                    # Update episode air date
                    episode_air_date = request.form.get(f'episode_air_date_{season["season_number"]}_{i}')
                    if episode_air_date:
                        episode['air_date'] = episode_air_date

        # Save updated data back to temp.json
        with open('temp.json', 'w') as f:
            json.dump(data, f, indent=4)
        
        # Save the movie or TV name in name.json
        new_name_entry = {'name': data['name']}
        try:
            with open('name.json', 'r') as name_file:
                existing_names = json.load(name_file)
        except FileNotFoundError:
            existing_names = []

        # Prevent duplicates
        if not any(entry['name'] == data['name'] for entry in existing_names):
            existing_names.append(new_name_entry)
        
        with open('name.json', 'w') as name_file:
            json.dump(existing_names, name_file, indent=4)

        return jsonify({"message": "Data updated successfully in temp.json and name.json"})
    else:
        return jsonify({"message": "Unauthorized access"}), 401


@app.route('/upload_data', methods=['POST'])
def upload_data():
    if 'admin_logged_in' in session:
        # Check if the uploaded file is present
        if 'data_file' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('home'))
        
        file = request.files['data_file']

        # Ensure the uploaded file is named 'data.db'
        if file.filename != 'data.db':
            flash("Please upload a file named data.db", "error")
            return redirect(url_for('home'))

        # Define the path to save data.db
        file_path = os.path.join(app.root_path, 'data.db')

        # If data.db already exists, remove it
        if os.path.exists(file_path):
            os.remove(file_path)

        # Save the new file
        file.save(file_path)
        flash("data.db uploaded successfully", "success")
        
        return redirect(url_for('home'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/upload_user_token', methods=['POST'])
def upload_user_token():
    if 'admin_logged_in' in session:
        # Check if the uploaded file is present
        if 'user_token' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('home'))
        
        file = request.files['user_token']

        # Ensure the uploaded file is named 'data.json'
        if file.filename != 'user_token.json':
            flash("Please upload a file named data.json", "error")
            return redirect(url_for('home'))

        # Define the path to save data.json
        file_path = os.path.join(app.root_path, 'user_token.json')

        # If data.json already exists, remove it
        if os.path.exists(file_path):
            os.remove(file_path)

        # Save the new file
        file.save(file_path)
        flash("user_token.json uploaded successfully", "success")
        
        return redirect(url_for('home'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/upload_user_token2', methods=['POST'])
def upload_user_token2():
    if 'admin_logged_in' in session:
        # Check if the uploaded file is present
        if 'user_token2' not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for('home'))
        
        file = request.files['user_token2']

        # Ensure the uploaded file is named 'data.json'
        if file.filename != 'user_token2.json':
            flash("Please upload a file named user_token2.json", "error")
            return redirect(url_for('home'))

        # Define the path to save data.json
        file_path = os.path.join(app.root_path, 'user_token2.json')

        # If data.json already exists, remove it
        if os.path.exists(file_path):
            os.remove(file_path)

        # Save the new file
        file.save(file_path)
        flash("user_token2.json uploaded successfully", "success")
        
        return redirect(url_for('home'))
    else:
        return redirect(url_for('admin_login'))

@app.route('/key/<key>')
def validate_key_via_url(key):
    # First check the key format
    if not key.startswith("FREExJAIxMARIOx"):
        abort(404)
    
    # Then validate the key
    is_valid, _ = validate_api_key(key)
    
    if is_valid:
        response = make_response(redirect(url_for('index', activation='success')))
        response.set_cookie('apiKey', key, max_age=60*60*24*30)
        return response
    else:
        abort(404)
        
@app.route('/download_data')
def download_data():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
        
    return send_file('data.db', as_attachment=True)

@app.route('/name_data')
def name_data():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
        
    return send_file('name.json', as_attachment=True)

@app.route('/get_token')
def get_token():
    # Step 1: Request a device code
    payload = {
        'client_id': CLIENT_ID,
        'scope': SCOPES
    }
    response = requests.post(DEVICE_CODE_URL, data=payload)
    if response.status_code != 200:
        return jsonify({"error": "Failed to get device code"}), 400
    
    device_code_data = response.json()
    
    # Step 2: Show the user where to log in and the device code
    print(f"Go to {device_code_data['verification_uri']} and enter the code: {device_code_data['user_code']}")
    
    # Step 3: Poll for the token
    token_data = poll_for_token(device_code_data['device_code'])
    
    if 'access_token' in token_data:
        with open('user_token.json', 'w') as token_file:
            json.dump(token_data, token_file)
        return jsonify({"message": "Token acquired successfully"})
    else:
        return jsonify({"error": "Failed to acquire token"}), 400

@app.route('/admin/edit/<imdb_id>/add_episode', methods=['POST'])
def add_episode(imdb_id):
    if 'admin_logged_in' not in session:
        abort(403)
    
    try:
        season_id = request.form.get('season_id')
        if not season_id:
            return jsonify({'error': 'Missing season ID'}), 400

        # Get current max episode number
        max_episode = query_db(
            "SELECT MAX(episode_number) as max_ep FROM episodes WHERE season_id = ?",
            (season_id,),
            one=True
        )['max_ep'] or 0

        # Insert new episode
        insert_db(
            """INSERT INTO episodes 
            (season_id, episode_number, name, description, thumbnail, air_date, file_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (season_id, max_episode + 1, 'New Episode', '', '', '', '')
        )

        # Update season episode count
        insert_db(
            "UPDATE seasons SET episode_count = ? WHERE id = ?",
            (max_episode + 1, season_id)
        )

        return '', 204

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/admin/edit/<imdb_id>/add_season', methods=['POST'])
def add_season(imdb_id):
    if 'admin_logged_in' not in session:
        abort(403)

    try:
        # Get show ID
        show = query_db("SELECT id FROM shows WHERE imdb_id = ?", (imdb_id,), one=True)
        if not show:
            return jsonify({'error': 'Show not found'}), 404

        # Get current max season
        max_season = query_db(
            "SELECT MAX(season_number) as max_season FROM seasons WHERE show_id = ?",
            (show['id'],),
            one=True
        )['max_season'] or 0

        # Insert new season
        season_id = insert_db(
            """INSERT INTO seasons 
            (show_id, season_number, episode_count)
            VALUES (?, ?, ?)""",
            (show['id'], max_season + 1, 1)
        )

        # Create first episode
        insert_db(
            """INSERT INTO episodes 
            (season_id, episode_number, name, description, thumbnail, air_date, file_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (season_id, 1, 'Episode 1', '', '', '', '')
        )

        return jsonify({'message': 'Season added'}), 201

    except sqlite3.Error as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

def poll_for_token(device_code):
    payload = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id': CLIENT_ID,
        'device_code': device_code,
        'scope': SCOPES
    }

    while True:
        time.sleep(5)
        response = requests.post(TOKEN_URL, data=payload)
        token_data = response.json()
        
        if 'access_token' in token_data:
            # Calculate the expiration time
            token_data['expires_at'] = int(time.time()) + token_data.get('expires_in', 0)
            
            # Ensure refresh_token is present
            if 'refresh_token' in token_data:
                with open('user_token.json', 'w') as token_file:
                    json.dump(token_data, token_file)
            else:
                print("Warning: No refresh token received!")
            
            return token_data
        elif token_data.get("error") == "authorization_pending":
            continue
        else:
            return token_data

def refresh_access_token():
    with open('user_token.json') as f:
        token_data = json.load(f)
    
    refresh_token = token_data.get('refresh_token')
    if not refresh_token:
        raise Exception("No refresh token available.")

    payload = {
        'grant_type': 'refresh_token',
        'client_id': CLIENT_ID,
        'scope': SCOPES,
        'refresh_token': refresh_token
    }

    response = requests.post(TOKEN_URL, data=payload)
    new_token_data = response.json()

    if 'access_token' in new_token_data:
        # Update the new expiration time
        new_token_data['expires_at'] = int(time.time()) + new_token_data.get('expires_in', 0)
        
        # Save the updated token data
        with open('user_token.json', 'w') as token_file:
            json.dump(new_token_data, token_file)

        return new_token_data['access_token']
    else:
        raise Exception("Failed to refresh access token")

def get_valid_token(token_file='user_token.json'):
    """Retrieve a valid access token from the specified token file."""
    try:
        with open(token_file) as f:
            token_data = json.load(f)
        
        # Check if token is expired or about to expire
        if token_data['expires_at'] < int(time.time()) + 120:
            # Refresh token logic
            refresh_token = token_data.get('refresh_token')
            if not refresh_token:
                raise Exception(f"No refresh token in {token_file}")

            payload = {
                'grant_type': 'refresh_token',
                'client_id': CLIENT_ID,
                'scope': SCOPES,
                'refresh_token': refresh_token
            }
            response = requests.post(TOKEN_URL, data=payload)
            new_token_data = response.json()

            if 'access_token' not in new_token_data:
                raise Exception("Failed to refresh token")

            # Update expiration time and save to the same token file
            new_token_data['expires_at'] = int(time.time()) + new_token_data.get('expires_in', 0)
            with open(token_file, 'w') as f:
                json.dump(new_token_data, f, indent=4)
            
            return new_token_data['access_token']
        else:
            return token_data['access_token']
    
    except Exception as e:
        print(f"Error in {token_file}: {str(e)}")
        return None

def get_existing_link(file_id, access_token):
    """Fetch existing shareable link if it exists."""
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    url = f"https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/permissions"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        for permission in data.get('value', []):
            if permission.get('link', {}).get('type') == 'view':
                return permission['link']['webUrl']
    return None

def get_onedrive_business_link(file_id, token_file='user_token.json', retry_count=3):
    """Generate a OneDrive link using the specified token file."""
    try:
        access_token = get_valid_token(token_file)
        if not access_token:
            return None

        headers = {"Authorization": f"Bearer {access_token}"}
        create_link_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/createLink"
        body = {"type": "view", "scope": "anonymous"}

        # Try to create a new link
        response = requests.post(create_link_url, headers=headers, json=body)
        if response.status_code == 200:
            return response.json()['link']['webUrl']
        
        # Fallback: Check existing links
        existing_link = get_existing_link(file_id, access_token)
        return existing_link

    except Exception as e:
        print(f"Error generating link: {str(e)}")
        return None

@app.route('/get_onedrive_link/<file_id>')
@login_required
def get_onedrive_link(file_id):
    if file_id.startswith("MARIO"):
        actual_file_id = file_id[5:]
        token_file = 'user_token2.json'
    else:
        actual_file_id = file_id
        token_file = 'user_token.json'
    
    if get_proxy_status():
        proxy_mappings = load_proxy_mappings()
        if actual_file_id not in proxy_mappings:
            proxy_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            proxy_mappings[actual_file_id] = proxy_id
            save_proxy_mappings(proxy_mappings)
        
        return jsonify({
            "link": f"{request.host_url}download/{proxy_mappings[actual_file_id]}"
        })
    else:
        link = get_onedrive_business_link(actual_file_id, token_file)
        return jsonify({"link": link}) if link else jsonify({"error": "Unable to generate link"}), 400


def fetch_data_from_tmdb(imdb_id):
    url = f'{BASE_URL}/find/{imdb_id}?api_key={TMDB_API_KEY}&external_source=imdb_id'
    response = requests.get(url)
    if response.status_code != 200:
        return None

    data = response.json()
    movie_results = data.get('movie_results', [])
    tv_results = data.get('tv_results', [])

    if movie_results:
        tmdb_id = movie_results[0]['id']
        return fetch_movie_data(tmdb_id)
    elif tv_results:
        tmdb_id = tv_results[0]['id']
        return fetch_tv_data(tmdb_id)
    else:
        return None

def fetch_movie_data(tmdb_id):
    url = f'{BASE_URL}/movie/{tmdb_id}?api_key={TMDB_API_KEY}&append_to_response=videos'
    response = requests.get(url)
    if response.status_code != 200:
        return None

    data = response.json()
    return {
        'type': 'movie',
        'imdb_id': data.get('imdb_id'),
        'name': data.get('title'),
        'thumbnail': f"https://image.tmdb.org/t/p/w500{data.get('poster_path')}",
        'rating': data.get('vote_average'),
        'description': data.get('overview'),
        'year': data.get('release_date', '').split('-')[0],
        'genres': [genre['name'] for genre in data.get('genres', [])],
        'trailer': get_trailer(data)
    }

def fetch_tv_data(tmdb_id):
    url = f'{BASE_URL}/tv/{tmdb_id}?api_key={TMDB_API_KEY}&append_to_response=videos,external_ids'
    response = requests.get(url)
    data = response.json()

    seasons = []
    for season in data.get('seasons', []):
        if season.get('season_number') != 0:
            season_data = {
                'season_number': season.get('season_number'),
                'episode_count': season.get('episode_count'),
                'episodes': fetch_episodes(tmdb_id, season.get('season_number'))
            }
            seasons.append(season_data)

    return {
        'type': 'tv',
        'imdb_id': data.get('external_ids', {}).get('imdb_id'),
        'name': data.get('name'),
        'thumbnail': f"https://image.tmdb.org/t/p/w500{data.get('poster_path')}",
        'rating': data.get('vote_average'),
        'description': data.get('overview'),
        'year': data.get('first_air_date', '').split('-')[0],
        'genres': [genre['name'] for genre in data.get('genres', [])],
        'trailer': get_trailer(data),
        'seasons': seasons
    }

@app.route('/admin/edit')
def edit_list():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    page = request.args.get('page', 1, type=int)
    filter_type = request.args.get('type', 'all')
    sort_by = request.args.get('sort', 'a-z')
    filter_quality = request.args.get('quality', 'all')
    search_query = request.args.get('search', '').strip()

    per_page = 20
    offset = (page - 1) * per_page

    query = "SELECT COUNT(*) FROM shows WHERE 1=1"
    params = []

    if filter_type != 'all':
        query += " AND type = ?"
        params.append(filter_type)

    if filter_quality != 'all':
        query += " AND quality = ?"
        params.append(filter_quality)

    if search_query:
        query += " AND LOWER(name) LIKE ?"
        params.append(f"%{search_query.lower()}%")

    total_items = query_db(query, params, one=True)["COUNT(*)"]
    total_pages = (total_items + per_page - 1) // per_page

    query = "SELECT id, imdb_id, name, type, year, quality FROM shows WHERE 1=1"
    params = []

    if filter_type != 'all':
        query += " AND type = ?"
        params.append(filter_type)

    if filter_quality != 'all':
        query += " AND quality = ?"
        params.append(filter_quality)

    if search_query:
        query += " AND LOWER(name) LIKE ?"
        params.append(f"%{search_query.lower()}%")

    if sort_by == 'a-z':
        query += " ORDER BY name ASC"
    elif sort_by == 'z-a':
        query += " ORDER BY name DESC"
    elif sort_by == 'year_asc':
        query += " ORDER BY year ASC"
    elif sort_by == 'year_desc':
        query += " ORDER BY year DESC"

    query += " LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    shows = query_db(query, params)
    
    return render_template('edit_list.html', 
                         shows=shows, 
                         page=page,
                         total_pages=total_pages,
                         filter_type=filter_type,
                         sort_by=sort_by,
                         filter_quality=filter_quality,
                         search_query=search_query)

@app.route('/admin/edit/<imdb_id>', methods=['GET', 'POST'])
def edit_item(imdb_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    show = query_db("SELECT * FROM shows WHERE imdb_id = ?", (imdb_id,), one=True)
    if not show:
        return "Show not found", 404

    if request.method == 'POST':
        try:
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE shows SET
                    name = ?, thumbnail = ?, rating = ?, description = ?, year = ?, quality = ?, file_id = ?
                WHERE imdb_id = ?
            """, (
                request.form['name'],
                request.form['thumbnail'],
                request.form['rating'],
                request.form['description'],
                request.form['year'],
                request.form['quality'],
                request.form.get('file_id', ''),
                imdb_id
            ))

            cursor.execute("DELETE FROM genres WHERE show_id = ?", (show['id'],))
            for genre in request.form.getlist('genres'):
                cursor.execute("INSERT INTO genres (show_id, genre) VALUES (?, ?)", (show['id'], genre))

            if show['type'] == 'tv':
                for key in request.form:
                    if key.startswith('episode_'):
                        parts = key.split('_')
                        field_type = parts[1]  # title, file, desc, thumb, date
                        season_num = parts[2]
                        episode_num = parts[3]

                        field_map = {
                            'title': 'name',
                            'file': 'file_id',
                            'desc': 'description',
                            'thumb': 'thumbnail',
                            'date': 'air_date'
                        }

                        if field_type in field_map:
                            cursor.execute(f"""
                                UPDATE episodes
                                SET {field_map[field_type]} = ?
                                WHERE season_id IN (SELECT id FROM seasons WHERE show_id = ? AND season_number = ?)
                                AND episode_number = ?
                            """, (request.form[key], show['id'], season_num, episode_num))

            conn.commit()
            flash('Changes saved successfully!', 'success')
            return redirect(url_for('edit_list'))

        except Exception as e:
            conn.rollback()
            flash(f'Error saving changes: {str(e)}', 'error')
        finally:
            conn.close()

    show['genres'] = [g['genre'] for g in query_db("SELECT genre FROM genres WHERE show_id = ?", (show['id'],))]
    if show['type'] == 'tv':
        seasons = query_db("SELECT * FROM seasons WHERE show_id = ? ORDER BY season_number", (show['id'],))
        for season in seasons:
            season['episodes'] = query_db("SELECT * FROM episodes WHERE season_id = ? ORDER BY episode_number", (season['id'],))
        show['seasons'] = seasons

    return render_template('edit_item.html', show=show)
    
def fetch_episodes(tmdb_id, season_number):
    url = f'{BASE_URL}/tv/{tmdb_id}/season/{season_number}?api_key={TMDB_API_KEY}'
    response = requests.get(url)
    if response.status_code != 200:
        return []

    data = response.json()
    episodes = []
    for episode in data.get('episodes', []):
        episodes.append({
            'name': episode.get('name'),
            'description': episode.get('overview'),
            'thumbnail': f"https://image.tmdb.org/t/p/w500{episode.get('still_path')}" if episode.get('still_path') else None,
            'rating': episode.get('vote_average'),
            'air_date': episode.get('air_date'),
            'episode_number': episode.get('episode_number'),
            'file_id': None
        })
    return episodes

def get_trailer(data):
    videos = data.get('videos', {}).get('results', [])
    for video in videos:
        if video['type'] == 'Trailer' and video['site'] == 'YouTube':
            return f"https://www.youtube.com/watch?v={video['key']}"
    return None

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    # Get total shows count
    total_shows = query_db("SELECT COUNT(*) AS count FROM shows", one=True)['count']
    total_pages = (total_shows + per_page - 1) // per_page

    if page < 1 or page > total_pages:
        abort(404)

    # Get paginated shows
    shows = query_db("""
        SELECT * FROM shows 
        ORDER BY date_added DESC 
        LIMIT ? OFFSET ?
    """, (per_page, offset))

    # Add genres to each show
    for show in shows:
        show['genres'] = [g['genre'] for g in 
                         query_db("SELECT genre FROM genres WHERE show_id=?", (show['id'],))]

    # Pagination display logic (same as before)
    visible_pages = []
    if total_pages <= 5:
        visible_pages = list(range(1, total_pages + 1))
    else:
        visible_pages.append(1)
        if page > 3:
            visible_pages.append("...")
        middle_start = max(2, page - 1)
        middle_end = min(total_pages - 1, page + 1)
        visible_pages.extend(range(middle_start, middle_end + 1))
        if page < total_pages - 2:
            visible_pages.append("...")
        visible_pages.append(total_pages)

    return render_template(
        'index.html',
        shows=shows,
        page=page,
        total_pages=total_pages,
        visible_pages=visible_pages
    )

    # Optionally sort the shows so new ones appear at the top (based on date added or year

# Show details route
@app.route('/show/<string:imdb_id>', defaults={'quality': None})
@app.route('/show/<string:imdb_id>/<string:quality>')
@login_required
def show(imdb_id, quality):
    show_data = query_db("""
        SELECT * FROM shows 
        WHERE imdb_id = ?
    """, (imdb_id,), one=True)

    if not show_data:
        abort(404)

    # Get genres
    show_data['genres'] = [g['genre'] for g in 
                          query_db("SELECT genre FROM genres WHERE show_id=?", (show_data['id'],))]

    # Get seasons and episodes if it's a TV show
    if show_data['type'] == 'tv':
        seasons = query_db("""
            SELECT * FROM seasons 
            WHERE show_id = ?
            ORDER BY season_number
        """, (show_data['id'],))
        
        for season in seasons:
            season['episodes'] = query_db("""
                SELECT * FROM episodes 
                WHERE season_id = ?
                ORDER BY episode_number
            """, (season['id'],))
        
        show_data['seasons'] = seasons

    return render_template('show.html', show=show_data, quality=quality)

# Admin login route

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        entered_name = request.form['name']
        entered_email = request.form['email']
        entered_password = request.form['password']

        # Read stored credentials from admin.json
        admins = read_admin_credentials()

        # Check if the entered credentials match any admin
        for admin in admins:
            if (entered_name == admin['name'] and 
                entered_email == admin['email'] and 
                entered_password == admin['password']):
                # If credentials match, set session and allow access to admin dashboard
                session['admin_logged_in'] = True
                return redirect(url_for('home'))

        # If no match found, show error message
        return render_template('admin_login.html', error="Invalid credentials. Please try again.")

    # If the user is already logged in, redirect to admin home
    if 'admin_logged_in' in session:
        return redirect(url_for('home'))

    # Show login page if GET request
    return render_template('admin_login.html')

def read_admin_credentials():
    # Read admin.json file
    if os.path.exists('admin.json'):
        with open('admin.json', 'r') as f:
            return json.load(f)
    return []

# Admin dashboard (protected route)
@app.route('/admin/home')
def home():
    if 'admin_logged_in' in session:
        return render_template('admin_dashboard.html')  # Render admin dashboard after login
    else:
        return redirect(url_for('admin_login'))

# Fetch data by IMDb ID (protected route)
@app.route('/fetch', methods=['POST'])
def fetch_data():
    if 'admin_logged_in' in session:
        imdb_id = request.form['imdb_id']
        data = fetch_data_from_tmdb(imdb_id)

        if data:
            # Store fetched data temporarily in temp.json for further operations
            with open('temp.json', 'w') as f:
                json.dump(data, f, indent=4)
            return render_template('show_data.html', data=data)
        else:
            return render_template('admin_dashboard.html', error="No data found for the given IMDb ID.")
    else:
        return redirect(url_for('admin_login'))

# Add File IDs for movies or episodes and save to data.json (protected route)
@app.route('/add_file_ids', methods=['POST'])
def add_file_ids():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    with open('temp.json', 'r') as f:
        data = json.load(f)

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Get quality from temp data
        quality = data.get('quality', '1080p')
        
        # Get file ID based on media type
        file_id = None
        if data['type'] == 'movie':
            file_id = request.form.get('file_id', '').strip()
        elif data['type'] == 'tv':
            file_id = None  # Not used for TV shows

        # Insert main show data
        cursor.execute("""
            INSERT INTO shows (
                imdb_id, type, name, thumbnail, rating,
                description, year, trailer, file_id, quality
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['imdb_id'],
            data['type'],
            data['name'],
            data['thumbnail'],
            data['rating'],
            data['description'],
            data['year'],
            data.get('trailer'),
            file_id,  # For movies
            quality
        ))
        show_id = cursor.lastrowid

        # Insert genres
        for genre in data['genres']:
            cursor.execute("INSERT INTO genres (show_id, genre) VALUES (?, ?)", 
                         (show_id, genre))

        # Handle TV show episodes
        if data['type'] == 'tv':
            for season in data['seasons']:
                cursor.execute("""
                    INSERT INTO seasons (show_id, season_number, episode_count)
                    VALUES (?, ?, ?)
                """, (show_id, season['season_number'], season['episode_count']))
                season_id = cursor.lastrowid

                for ep_idx, episode in enumerate(season['episodes']):
                    form_field = f'file_id_{season["season_number"]}_{ep_idx}'
                    episode_file_id = request.form.get(form_field, '').strip()
                    
                    cursor.execute("""
                        INSERT INTO episodes (
                            season_id, episode_number, name,
                            description, thumbnail, rating,
                            air_date, file_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        season_id,
                        episode['episode_number'],
                        episode.get('name'),
                        episode.get('description'),
                        episode.get('thumbnail'),
                        episode.get('rating'),
                        episode.get('air_date'),
                        episode_file_id
                    ))

        conn.commit()
        flash("Data saved successfully!", "success")
    except sqlite3.Error as e:
        conn.rollback()
        flash(f"Database error: {str(e)}", "error")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for('home'))
        
@app.route('/submit_report', methods=['POST'])
def submit_report():
    try:
        data = request.get_json()
        access_token = get_valid_token()
        
        # Build email content
        email_body = f"""
<html>
<body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2 style="color: #4CAF50;">New Content Report</h2>
    <table style="border-collapse: collapse; width: 100%;">
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Content Type:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('type', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Issue Type:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('issueType', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Email:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('email', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Title:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('showName', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>IMDb ID:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('showId', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Season:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('season', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Episode:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('episode', 'N/A')}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Report Details:</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{data.get('comment', 'No comments provided')}</td></tr>
    </table>
</body>
</html>
"""

        # Microsoft Graph API request
        url = "https://graph.microsoft.com/v1.0/me/sendMail"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        email_data = {
            "message": {
                "subject": f"Content Report: {data.get('showName', 'Unknown Title')}",
                "body": {"contentType": "HTML", "content": email_body},
                "toRecipients": [{"emailAddress": {"address": "Mario22623@gmail.com"}}],
            },
            "saveToSentItems": "true"
        }

        response = requests.post(url, headers=headers, json=email_data)
        if response.status_code == 202:
            return jsonify({"message": "Report submitted successfully!"}), 200
        else:
            app.logger.error(f"Report failed: {response.status_code} - {response.text}")
            return jsonify({"error": "Failed to submit report"}), 500

    except Exception as e:
        app.logger.error(f"Report error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
        

@app.route('/send_email', methods=['POST'])
def send_email():
    try:
        # Get the valid access token
        access_token = get_valid_token()
        
        # Extract data from the JSON request
        data = request.get_json()
        recipient_email = data.get('recipient', 'N/A')  # Requester's email
        body = data.get('body', '') 

        # Parse body fields
        parsed_fields = {field.split(":")[0].strip(): field.split(":")[1].strip() 
                        for field in body.split("\n") if ":" in field}

        # Extract individual fields
        email_type = parsed_fields.get("Type", "N/A")
        name = parsed_fields.get("Name", "N/A")
        year = parsed_fields.get("Year", "N/A")
        comments = parsed_fields.get("Comments", "N/A")

        # Validate required fields
        if not body or not recipient_email:
            return jsonify({"error": "Missing required fields"}), 400

        # Store request in database
        with sqlite3.connect('data.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO requests (name, year, media_type, email)
                VALUES (?, ?, ?, ?)
            ''', (name, year, email_type, recipient_email))
            conn.commit()

        # Email configurations
        admin_email = "Mario22623@gmail.com"
        url = "https://graph.microsoft.com/v1.0/me/sendMail"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        # User Confirmation Email
        user_email_body = f"""
<html>
  <body style="margin: 0; padding: 0; background-color: #141414; font-family: Arial, sans-serif;">
    <div style="width: 100%; display: flex; justify-content: center; padding: 40px 0;">
      <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #1c1c1c; border: 1px solid #e50914; color: #ffffff; border-radius: 0;">
        <tr>
          <td style="padding: 20px 30px; text-align: center; border-bottom: 1px solid #e50914;">
            <h2 style="color: #e50914; font-size: 24px; margin: 0;">REQUEST RECEIVED</h2>
            <p style="margin-top: 5px; font-size: 14px; color: #aaa;">Your request has been logged in AuroraFlix</p>
          </td>
        </tr>
        <tr>
          <td style="padding: 30px;">
            <p style="margin-bottom: 15px;">Hello,</p>
            <p>We’ve received your request for the <strong>{email_type}</strong> "<span style="color: #e50914;">{name} ({year})</span>".</p>
            <p style="margin-top: 20px; color: #ccc;">Here are the details:</p>
            <table width="100%" cellpadding="8" cellspacing="0" style="margin-top: 10px;">
              <tr>
                <td style="width: 100px; color: #999; font-weight: bold;">Type:</td>
                <td style="color: #fff;">{email_type}</td>
              </tr>
              <tr>
                <td style="color: #999; font-weight: bold;">Year:</td>
                <td style="color: #fff;">{year}</td>
              </tr>
              <tr>
                <td style="color: #999; font-weight: bold;">Comment:</td>
                <td style="color: #fff;">{comments}</td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="text-align: center; padding: 20px; border-top: 1px solid #e50914;">
            <p style="font-size: 12px; color: #888; margin: 0;">This is an automated email from <strong>AuroraFlix</strong></p>
            <p style="font-size: 12px; color: #444; margin: 5px 0 0;">&copy; 2024 AuroraFlix</p>
          </td>
        </tr>
      </table>
    </div>
  </body>
</html>
"""

        # Admin Notification Email
        admin_email_body = f"""
<html>
  <body style="margin: 0; padding: 20px; font-family: Arial, sans-serif; background-color: #121212; color: #ffffff;">
    <h2 style="color: #00ff00;">New Content Report</h2>
    <table width="100%" cellpadding="10" cellspacing="0" border="0" style="border-collapse: collapse; background-color: #1e1e1e; border: 1px solid #333;">
      <tr>
        <td style="border: 1px solid #333;"><strong>Content Type:</strong></td>
        <td style="border: 1px solid #333;">{email_type}</td>
      </tr>
      <tr>
        <td style="border: 1px solid #333;"><strong>Name:</strong></td>
        <td style="border: 1px solid #333;">{name}</td>
      </tr>
      <tr>
        <td style="border: 1px solid #333;"><strong>Year:</strong></td>
        <td style="border: 1px solid #333;">{year}</td>
      </tr>
      <tr>
        <td style="border: 1px solid #333;"><strong>Email:</strong></td>
        <td style="border: 1px solid #333;">{recipient_email}</td>
      </tr>
      <tr>
        <td style="border: 1px solid #333;"><strong>Comments:</strong></td>
        <td style="border: 1px solid #333;">{comments}</td>
      </tr>
    </table>
    <p style="margin-top: 20px; font-size: 12px; color: #aaa;">&copy; 2024 AuroraFlix | Auto Notification</p>
  </body>
</html>
"""
        # Send both emails
        email_responses = []
        
        # Send user confirmation
        user_email_data = {
            "message": {
                "subject": "Your Request Submission Confirmation",
                "body": {"contentType": "HTML", "content": user_email_body},
                "toRecipients": [{"emailAddress": {"address": recipient_email}}],
            },
            "saveToSentItems": "true",
        }
        user_response = requests.post(url, headers=headers, json=user_email_data)
        email_responses.append(("User", user_response))

        # Send admin notification
        admin_email_data = {
            "message": {
                "subject": f"New Request: {email_type} - {name}",
                "body": {"contentType": "HTML", "content": admin_email_body},
                "toRecipients": [{"emailAddress": {"address": admin_email}}],
            },
            "saveToSentItems": "true",
        }
        admin_response = requests.post(url, headers=headers, json=admin_email_data)
        email_responses.append(("Admin", admin_response))

        # Check responses
        errors = []
        for recipient, response in email_responses:
            if response.status_code != 202:
                errors.append(f"Failed to send {recipient} email: {response.text}")

        if errors:
            return jsonify({
                "message": "Partial success with some email failures",
                "errors": errors
            }), 207

        return jsonify({"message": "Both emails sent successfully!"}), 200

    except sqlite3.Error as db_error:
        print("Database error:", db_error)
        return jsonify({"error": "Database operation failed"}), 500
        
    except Exception as e:
        print("Exception occurred:", e)
        return jsonify({"error": "An error occurred while processing the request"}), 500


@app.route('/admin/logout')
def admin_logout():
    # Log out the admin and clear the session
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/search')
def enhanced_search():
    try:
        # Get and sanitize search query
        raw_query = request.args.get('q', '').strip()
        clean_query = ' '.join(raw_query.split()).replace('+', ' ')  # Handle URL encoding
        search_term = f"%{clean_query.lower()}%"
        
        if not clean_query:
            return redirect(url_for('index'))

        conn = get_db()
        cursor = conn.cursor()

        # Verify database schema first
        cursor.execute("PRAGMA table_info(shows)")
        columns = [col[1] for col in cursor.fetchall()]
        required_columns = {'quality', 'name', 'imdb_id', 'type'}
        if not required_columns.issubset(columns):
            raise ValueError("Database missing required columns")

        # New optimized query with EXPLICIT column list
        cursor.execute("""
            SELECT 
                s.id,
                s.imdb_id,
                s.type,
                s.name,
                s.thumbnail,
                s.rating,
                s.description,
                s.year,
                s.quality,
                COALESCE(GROUP_CONCAT(g.genre), '') AS genres
            FROM shows s
            LEFT JOIN genres g ON s.id = g.show_id
            WHERE LOWER(s.name) LIKE ?
            GROUP BY s.id
            ORDER BY s.date_added DESC
        """, (search_term,))

        # Safe result processing
        shows = []
        for row in cursor.fetchall():
            show = {
                'id': row[0],
                'imdb_id': row[1],
                'type': row[2],
                'name': row[3],
                'thumbnail': row[4],
                'rating': row[5],
                'description': row[6],
                'year': row[7],
                'quality': row[8],
                'genres': row[9].split(',') if row[9] else []
            }
            shows.append(show)

        return render_template('search_results.html',
                             shows=shows,
                             query=clean_query)

    except sqlite3.Error as e:
        app.logger.error(f"Database error in search: {str(e)}")
        return "Search service unavailable. Try again later.", 503
    except ValueError as e:
        app.logger.critical(f"Database schema mismatch: {str(e)}")
        return "Configuration error. Contact support.", 500
    except Exception as e:
        app.logger.error(f"Unexpected search error: {str(e)}")
        return "An unexpected error occurred.", 500
    finally:
        if 'conn' in locals():
            conn.close()

def load_temp_pages():
    """Load temp pages from JSON file."""
    if os.path.exists(TEMP_PAGES_FILE):
        with open(TEMP_PAGES_FILE, "r") as f:
            return json.load(f)
    return {}

def save_temp_pages(temp_pages):
    """Save temp pages to JSON file."""
    with open(TEMP_PAGES_FILE, "w") as f:
        json.dump(temp_pages, f, indent=4)

def generate_random_path():
    """Generate a random string for the temporary URL."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def delete_expired_pages():
    """Delete expired pages from JSON file periodically."""
    while True:
        try:
            with temp_pages_lock:
                temp_pages = load_temp_pages()
                current_time = time.time()
                temp_pages = {k: v for k, v in temp_pages.items() if current_time <= v["expiry"]}

                save_temp_pages(temp_pages)
                print(f"Cleanup complete. Active temp pages: {len(temp_pages)}")
        except Exception as e:
            print(f"Error in cleanup thread: {e}")
        
        time.sleep(60)  # Check every minute

# Start the cleanup thread
threading.Thread(target=delete_expired_pages, daemon=True).start()

def get_freemode_status():
    try:
        with open('freemode.json', 'r') as f:
            data = json.load(f)
            return data.get('freemode', 'off').lower() == 'on'
    except (FileNotFoundError, json.JSONDecodeError):
        return False

@app.route("/generate", methods=["POST"])
def generate():
    try:
        # Step 1: Generate key
        response = requests.get(KEY_API_URL)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch key"}), 500

        key_data = response.json()
        key = key_data.get("key", "No Key Found")

        # Step 2: Create temporary page
        temp_path = generate_random_path()
        expiry_time = time.time() + 600  # 10 minutes

        with temp_pages_lock:
            temp_pages = load_temp_pages()
            temp_pages[temp_path] = {"key": key, "expiry": expiry_time}
            save_temp_pages(temp_pages)

        temp_url = f"https://auroraflix.onrender.com/{temp_path}"
        freemode_active = get_freemode_status()

        # Step 3: Shorten URL if needed
        short_url = temp_url
        if not freemode_active:
            try:
                gp_link_api = f"https://api.gplinks.com/api?api={GP_API_KEY}&url={temp_url}"
                gp_response = requests.get(gp_link_api, timeout=30)
                if gp_response.status_code == 200:
                    short_url = gp_response.json().get("shortenedUrl", temp_url)
            except requests.exceptions.RequestException as e:
                app.logger.error(f"URL shortening failed: {str(e)}")

        return jsonify({
            "temp_url": temp_url,
            "short_url": short_url,
            "freemode": freemode_active
        })

    except Exception as e:
        app.logger.error(f"Key generation failed: {str(e)}")
        return jsonify({"error": "Key generation process failed"}), 500

    return jsonify({"temp_url": temp_url, "short_url": short_url})
    
@app.route("/<temp_id>")
def temp_page(temp_id):
    """Display the temporary page if it exists and is not expired."""
    with temp_pages_lock:
        temp_pages = load_temp_pages()
        temp_data = temp_pages.get(temp_id)

        if not temp_data or time.time() > temp_data["expiry"]:
            return render_template("404.html"), 404  # Return 404 for expired pages

    return render_template("temp_page.html", key=temp_data["key"])

@app.route('/toggle_freemode', methods=['POST'])
def toggle_freemode():
    if 'admin_logged_in' not in session:
        return jsonify({"message": "Unauthorized"}), 403

    try:
        # Create file if not exists
        if not os.path.exists('freemode.json'):
            with open('freemode.json', 'w') as f:
                json.dump({"freemode": "off"}, f)

        with open('freemode.json', 'r+') as f:
            data = json.load(f)
            data['freemode'] = 'on' if data.get('freemode', 'off') == 'off' else 'off'
            f.seek(0)
            json.dump(data, f, indent=4)
            f.truncate()

        return jsonify({
            "message": f"Freemode {'activated' if data['freemode'] == 'on' else 'deactivated'}",
            "freemode": data['freemode']
        }), 200

    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500



# Admin Routes
@app.route('/admin/requests')
def admin_requests():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    with sqlite3.connect('data.db') as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM requests WHERE status = ? ORDER BY id DESC', ('pending',))
        requests = cursor.fetchall()
    
    return render_template('admin_requests.html', requests=requests)

@app.route('/admin/update_status', methods=['POST'])
def update_status():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    request_id = request.form.get('request_id')
    new_status = request.form.get('status')
    
    try:
        with sqlite3.connect('data.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE requests 
                SET status = ?
                WHERE id = ?
            ''', (new_status, request_id))
            
            if new_status == 'completed':
                cursor.execute('''
                    SELECT name, year, media_type, email 
                    FROM requests 
                    WHERE id = ?
                ''', (request_id,))
                req = cursor.fetchone()
                
                if req:
                    access_token = get_valid_token()
                    if not access_token:
                        flash('Failed to get access token', 'error')
                        return redirect(url_for('admin_requests'))
                    
                    send_email1(
                        access_token=access_token,
                        to_email=req['email'],
                        name=req['name'],
                        year=req['year'],
                        media_type=req['media_type']
                    )
                    flash('Status updated and confirmation email sent!', 'success')
                else:
                    flash('Request not found!', 'error')
            else:
                flash('Status updated successfully!', 'success')
            
            conn.commit()
            
    except Exception as e:
        print(f"Error updating status: {str(e)}")
        flash('Error updating status', 'error')
    
    return redirect(url_for('admin_requests'))

def send_email1(access_token, to_email, name, year, media_type):
    subject = "Your Request Has Been Successfully Added"
    
    html_body = f"""
<html style="background-color:#000;">
<head>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap');
    .icon {{
      width: 20px;
      height: 20px;
      vertical-align: middle;
      margin-right: 8px;
    }}
  </style>
</head>
<body style="margin:0; padding:0; background-color:#000; font-family:'Inter', sans-serif; color:#fff;">
  <table align="center" width="100%" cellpadding="0" cellspacing="0" style="padding: 0; background-color:#000;">
    <tr>
      <td>
        <table align="center" width="600" cellpadding="0" cellspacing="0" style="background-color:#141414; padding: 0; border: 2px solid #e50914;">
          <tr>
            <td style="text-align:center; padding: 40px 30px 10px;">
              <h2 style="font-size:24px; color:#e50914; margin:0; letter-spacing: 0.5px;">
                <svg class="icon" fill="#e50914" viewBox="0 0 20 20"><path d="M7.629 13.918L3.08 9.369l1.41-1.41 3.14 3.14 7.88-7.88 1.41 1.41z"/></svg>
                REQUEST ADDED
              </h2>
              <p style="font-size:14px; color:#bbb; margin-top:6px;">
                <svg class="icon" fill="#bbb" viewBox="0 0 20 20"><path d="M2 4.5A2.5 2.5 0 014.5 2h11A2.5 2.5 0 0118 4.5v11a2.5 2.5 0 01-2.5 2.5h-11A2.5 2.5 0 012 15.5v-11zM4 4v12h12V4H4z"/></svg>
                Your content is now available on AuroraFlix
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 30px 0; font-size:15px; line-height:1.6;">
              <p>Hello,</p>
              <p>
                We're excited to inform you that your request for the <strong>{media_type}</strong> 
                <span style="color:#e50914;">"{name} ({year})"</span> has been successfully added to our platform.
              </p>
              <p>You can begin watching it right away at the link below:</p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding: 30px 0;">
              <a href="https://auroraflix.onrender.com" target="_blank" 
                 style="display:inline-block; background-color:#e50914; color:#fff; font-weight:600; text-decoration:none; padding:14px 32px; border: none; font-size:15px; text-transform:uppercase;">
                <svg class="icon" fill="#fff" viewBox="0 0 20 20" style="margin-right:8px;"><path d="M4 4l12 6-12 6z"/></svg>
                Watch Now
              </a>
            </td>
          </tr>
          <tr>
            <td style="padding: 0 30px 40px; font-size:15px; color:#bbb;">
              <p>Thank you for choosing <strong style="color:#fff;">AuroraFlix</strong>.</p>
              <p>Enjoy your viewing!</p>
              <br>
              <p style="color:#666; font-size:13px;">– AuroraFlix Team</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    email_msg = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_body
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": to_email
                    }
                }
            ]
        }
    }

    response = requests.post(f"{GRAPH_ENDPOINT}/me/sendMail", headers=headers, json=email_msg)
    return response.status_code == 202


@app.route('/freemode_status', methods=['GET'])
def freemode_status():
    try:
        if not os.path.exists('freemode.json'):
            return jsonify({"freemode": "off"})
            
        with open('freemode.json', 'r') as f:
            data = json.load(f)
            return jsonify({"freemode": data.get('freemode', 'off')})
    except:
        return jsonify({"freemode": "off"})

if __name__ == '__main__':
    # Initialize network metrics
    last_net_io = psutil.net_io_counters()
    last_net_time = datetime.now()
    app.run(host='0.0.0.0', port=5000, debug=True)
