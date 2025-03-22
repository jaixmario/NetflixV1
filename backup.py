import time
import requests
import os
import json
from datetime import datetime

UPLOAD_INTERVAL = 30  # 1 hour
BACKUP_FOLDER_ID = "01ZDEC6CXCKCNDJGM7X5EK33GFMY6DW5TL"
TOKEN_FILE = "user_token.json"

CLIENT_ID = '59790544-ca0c-4b77-b338-26ff9d1b676f'
TENANT_ID = '0fd666e8-0b3d-41ea-a5ef-1c509130bd94'
DEVICE_CODE_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode'
TOKEN_URL = f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token'
SCOPES = "openid profile email offline_access https://graph.microsoft.com/.default"

def refresh_access_token():
    """Refresh the expired access token and update user_token.json."""
    try:
        with open(TOKEN_FILE, 'r') as f:
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
            new_token_data['expires_at'] = int(time.time()) + new_token_data.get('expires_in', 0)

            # Save updated token data
            with open(TOKEN_FILE, 'w') as token_file:
                json.dump(new_token_data, token_file, indent=4)

            return new_token_data['access_token']
        else:
            raise Exception(f"Token refresh failed: {new_token_data.get('error_description', 'Unknown error')}")

    except Exception as e:
        print(f"Error refreshing token: {e}")
        return None


def get_access_token():
    """Retrieve a valid access token, refreshing it if needed."""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token_data = json.load(f)

        if token_data.get('expires_at', 0) < int(time.time()) + 120:
            print("Access token expired. Refreshing...")
            return refresh_access_token()

        return token_data.get('access_token')

    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: user_token.json not found or corrupted.")
        return None


def upload_to_onedrive():
    """Uploads data.db to OneDrive every 1 hour with token refresh."""
    while True:
        time.sleep(UPLOAD_INTERVAL)

        access_token = get_access_token()
        if not access_token:
            print("Error: Unable to get a valid access token.")
            continue  # Skip this cycle and retry later

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data{timestamp}.db"
        upload_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{BACKUP_FOLDER_ID}:/{filename}:/content"

        try:
            with open('data.db', 'rb') as file_data:
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/octet-stream'
                }
                response = requests.put(upload_url, headers=headers, data=file_data)

            if response.status_code in [200, 201]:
                print(f"{filename} uploaded successfully.")
            else:
                print(f"Error uploading {filename}: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"Error in backup process: {e}")


if __name__ == "__main__":
    upload_to_onedrive()