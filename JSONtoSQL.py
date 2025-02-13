import json
import sqlite3
import ast

def parse_genres(genre_str):
    """Convert genre string like "['Drama', 'Romance']" to list"""
    try:
        return ast.literal_eval(genre_str.replace("'", '"'))
    except:
        return []

# Connect to SQLite database
conn = sqlite3.connect('data.db')
cursor = conn.cursor()

with open('data.json', 'r') as f:
    data = json.load(f)

for item in data:
    # Insert into shows table
    cursor.execute('''
        INSERT OR IGNORE INTO shows (
            imdb_id, type, name, thumbnail, rating, description,
            year, trailer, file_id, quality, date_added
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        item['imdb_id'],
        item['type'],
        item['name'],
        item['thumbnail'],
        float(item['rating']) if item['rating'] else None,
        item['description'],
        int(item['year']),
        item.get('trailer'),
        item.get('file_id'),
        item.get('quality', '1080p'),
        item['date_added']
    ))
    
    # Get the inserted show's ID
    cursor.execute('SELECT id FROM shows WHERE imdb_id = ?', (item['imdb_id'],))
    show_id = cursor.fetchone()[0]
    
    # Insert genres
    for genre in parse_genres(item['genres'][0]):
        cursor.execute('''
            INSERT OR IGNORE INTO genres (show_id, genre)
            VALUES (?, ?)
        ''', (show_id, genre.strip()))
    
    # Insert seasons and episodes for TV shows
    if item['type'] == 'tv':
        for season in item['seasons']:
            cursor.execute('''
                INSERT INTO seasons (show_id, season_number, episode_count)
                VALUES (?, ?, ?)
            ''', (show_id, season['season_number'], season['episode_count']))
            season_id = cursor.lastrowid
            
            for episode in season['episodes']:
                cursor.execute('''
                    INSERT INTO episodes (
                        season_id, episode_number, name,
                        description, thumbnail, rating,
                        air_date, file_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    season_id,
                    episode['episode_number'],
                    episode['name'],
                    episode['description'],
                    episode['thumbnail'],
                    float(episode['rating']) if episode['rating'] else None,
                    episode['air_date'],
                    episode['file_id']
                ))

conn.commit()
conn.close()