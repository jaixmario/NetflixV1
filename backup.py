import time
import requests
import os
import json
from datetime import datetime

UPLOAD_INTERVAL = 3600 # 1 hour
BACKUP_FOLDER_ID = "01ZDEC6CXCKCNDJGM7X5EK33GFMY6DW5TL"  # OneDrive folder ID
TOKEN_FILE = "user_token.json"  # Store the access token here


def get_access_token():
    """Retrieve a valid access token from user_token.json."""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token_data = json.load(f)

        # Check if token is expired or about to expire
        if token_data.get('expires_at', 0) < int(time.time()) + 120:
            print("Access token expired. Please refresh manually.")
            return None

        return token_data.get('access_token')

    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: user_token.json not found or corrupted.")
        return None


def upload_to_onedrive():
    """Uploads data.db to OneDrive every 1 hour."""
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
