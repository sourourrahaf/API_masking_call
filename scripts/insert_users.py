import psycopg2
from dotenv import load_dotenv
import os
import bcrypt  # securiser les mdp

load_dotenv()

def get_db_connection():
    return psycopg2.connect(os.getenv('DATABASE_URL'))

users_data = [
    {"username": "khairia", "password": "adminpass123", "real_number": "+21692111111", "scope": "admin"},
    {"username": "fawzi", "password": "adminpass456", "real_number": "+21692222222", "scope": "admin"},
    {"username": "khalil", "password": "adminpass789", "real_number": "+21692333333", "scope": "admin"},
    {"username": "rayen", "password": "password120", "real_number": "+21692444444", "scope": "user"},
    {"username": "ahmed", "password": "password121", "real_number": "+21692555555", "scope": "user"},
    {"username": "aya", "password": "password122", "real_number": "+21696111111", "scope": "user"},
    {"username": "hanin", "password": "password123", "real_number": "+21696222222", "scope": "user"},
    {"username": "ranim", "password": "password124", "real_number": "+21696333333", "scope": "user"},
    {"username": "maram", "password": "password125", "real_number": "+21696444444", "scope": "user"},
    {"username": "ali", "password": "password126", "real_number": "+21696555555", "scope": "user"},   
    {"username": "omar", "password": "password127", "real_number": "+21697111111", "scope": "user"},
    {"username": "youssef", "password": "password128", "real_number": "+21697222222", "scope": "user"},
    {"username": "achref", "password": "password129", "real_number": "+21697333333", "scope": "user"},
    {"username": "oumayma", "password": "userpass121", "real_number": "+2197444444", "scope": "user"},
    {"username": "imen", "password": "userpass122", "real_number": "+21697555555", "scope": "user"},
    {"username": "rouaida", "password": "userpass123", "real_number": "+21698111111", "scope": "user"},
    {"username": "tarnim", "password": "userpass124", "real_number": "+21698222222", "scope": "user"},
    {"username": "darine", "password": "userpass125", "real_number": "+21698333333", "scope": "user"},
    {"username": "ghada", "password": "userpass126", "real_number": "+21698444444", "scope": "user"},
    {"username": "siwar", "password": "userpass127", "real_number": "+21698555555", "scope": "user"},

]

try:
    conn = get_db_connection()
    cur = conn.cursor()
    
    for user in users_data:
        hashed_password = bcrypt.hashpw(user['password'].encode(), bcrypt.gensalt()).decode()  # Hashage sécurisé
        cur.execute("""
            INSERT INTO users (username, password, real_number, scope)
            VALUES (%s, %s, %s, %s);
        """, (user['username'], hashed_password, user['real_number'], user['scope']))
    
    conn.commit()
    cur.close()
    conn.close()
    print("Utilisateurs insérés avec succès !")

except Exception as e:
    print(f"Erreur : {e}")