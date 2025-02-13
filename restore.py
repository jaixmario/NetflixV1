import json
import time
import requests
import os

#  Replace these with your actual values
CLIENT_ID = '59790544-ca0c-4b77-b338-26ff9d1b676f'
TENANT_ID = '0fd666e8-0b3d-41ea-a5ef-1c509130bd94'
SCOPES = "openid profile email offline_access https://graph.microsoft.com/.default"
TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'


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
        new_token_data['expires_at'] = int(time.time()) + new_token_data.get('expires_in', 0)
        
        with open('user_token.json', 'w') as token_file:
            json.dump(new_token_data, token_file)

        return new_token_data['access_token']
    else:
        raise Exception("Failed to refresh access token")

def download_and_replace_file():
    try:
        # Refresh access token
        access_token = refresh_access_token()
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        folder_id = "01ZDEC6CXCKCNDJGM7X5EK33GFMY6DW5TL"
        
        # Get latest file in the folder
        graph_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_id}/children"
        params = {
            '$orderby': 'lastModifiedDateTime desc',
            '$top': 1
        }

        response = requests.get(graph_url, headers=headers, params=params)
        response.raise_for_status()

        files = response.json().get('value', [])
        
        if not files:
            print("No files found in the specified folder.")
            return

        latest_file = files[0]
        download_url = latest_file.get('@microsoft.graph.downloadUrl')
        original_name = latest_file.get('name')

        if not download_url:
            raise Exception("No download URL available for the file.")

        # Download to temporary file
        temp_file = "temp_download.tmp"
        with open(temp_file, 'wb') as f:
            file_response = requests.get(download_url)
            file_response.raise_for_status()
            f.write(file_response.content)

        # Check and delete existing keys_database.sqlite
        target_file = "data.db"
        if os.path.exists(target_file):
            os.remove(target_file)
            print(f"Deleted existing {target_file}")

        # Rename downloaded file to keys_database.sqlite
        os.rename(temp_file, target_file)
        print(f"Successfully replaced with {original_name} -> {target_file}")

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.text}")
    except Exception as e:
        # Clean up temporary file if something went wrong
        if os.path.exists(temp_file):
            os.remove(temp_file)
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    download_and_replace_file()