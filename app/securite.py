
import os # Pour accéder aux variables d'environnement  
import bcrypt # Pour le hachage des mots de passe (contre les attaques par dictionnaire)
import jwt # PyJWT pour la gestion des tokens JWT (authentification sécurisée)
from datetime import datetime, timedelta
from fastapi import HTTPException, Request
from cryptography.fernet import Fernet  # Chiffrement symétrique Fernet pour protéger les mappings sensibles
import json # Pour convertir les dictionnaires en JSON avant chiffrement
from dotenv import load_dotenv # Charger les variables d'environnement depuis .env (sécurisé contre l'exposition de clés
import re  # Pour les expressions régulières dans la validation (ex. : formats stricts pour éviter les caractères dangereux)
from pydantic import BaseModel, field_validator  # Pour définir et valider les modèles JSON (contre OWASP : prévention des injections)
import logging  # Pour journaliser les erreurs internes de manière sécurisée
import psycopg2 #connexion à PostgreSQL



# Charger les variables d'environnement depuis le fichier .env (évite de hardcoder les secrets)
load_dotenv()
#---------------------------------- JWT -------------------------------------
# Classe pour les paramètres de sécurité (ex. : clé JWT)
class Settings(BaseModel):
    authjwt_secret_key: str = os.getenv("JWT_SECRET")
#fonction de creation de token JWT
def create_jwt_token(username: str, hours_valid: int = 1) -> str:
         # Récupérer le scope depuis la DB (ajoutez une fonction helper si besoin)
         conn = psycopg2.connect(os.getenv('DATABASE_URL'))  # Utilisez get_db_connection si importé
         cur = conn.cursor()
         cur.execute("SELECT scope FROM users WHERE username = %s", (username,)) #requête SQL pour récupérer le champ scope de la table users correspondant à l’utilisateur dont le username est passé à la fonction
         result = cur.fetchone()
         conn.close()
         scope = result[0] if result else "user"  # Défaut si non trouvé
         
         payload = {
             "sub": username,
             "scope": scope,
             "exp": datetime.utcnow() + timedelta(hours=hours_valid)
         }
         token = jwt.encode(payload, os.getenv('JWT_SECRET_KEY'), algorithm="HS256")
         return token 
# fonction Vérifie la validité du JWT envoyé dans l'en-tête Authorization.Si le token est invalide ou absent, lève HTTPException 401
async def jwt_required(request: Request):
    auth_header = request.headers.get('Authorization')

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            jwt.decode(token, os.getenv('JWT_SECRET_KEY'), algorithms=["HS256"])
            return  
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expiré")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Token invalide")

    # Si aucun header Authorization n'est présent
    raise HTTPException(status_code=401, detail="Token requis")

   

#--------------------------validation des input ----------------------------
# -------Classe pour définir le format du body de masquage des appels (avec validation stricte pour sécurité)
class MaskRequest(BaseModel):   
    caller_real: str  # Numéro appelant réel
    callee_real: str  # Numéro appelé réel
    
    @field_validator('caller_real', 'callee_real')
    # Validation stricte du format tunisien pour prévenir les injections et les données malformées (OWASP : Injection)
    def validate_phone(cls, v):
        if not re.match(r'^\+216\d{8}$', v):  # Format exact : +216 suivi de 8 chiffres
            raise ValueError('Numéro invalide : doit être au format +216XXXXXXXX')
        return v
    # Validation pour éviter les numéros identiques
  # Nouveau validator pour éviter les numéros identiques
    @field_validator('callee_real')
    def validate_not_identical(cls, v, info):
      if 'caller_real' in info.data and v == info.data['caller_real']:
          raise ValueError('Numéros identiques interdits')
      return v
# ----------Classe pour définir le format du body d'authentification (avec validation pour renforcer la sécurité)
class LoginRequest(BaseModel):  
    username: str
    password: str
    
    
    @field_validator('username')
    # Validation pour éviter les usernames dangereux (OWASP : Injection, prévention des caractères spéciaux)
    def validate_username(cls, v):  
        if len(v) < 3 or len(v) > 50 or not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username invalide : 3-50 caractères alphanumériques')
        return v
    
    # Validation de longueur minimale pour renforcer l'authentification (OWASP : Authentification brisée)
    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Mot de passe trop court : minimum 8 caractères')
        return v
#---------------------- hashage de mot de passe des users -------------------
#fonction de hasher les mdp
def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
# fonction de Vérifie un mot de passe avec le hash stocké
def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
#----------------------------- chiffrement mapping -------------------------------------
# Gestion de la clé secrète pour le chiffrement (chargée depuis .env pour éviter l'exposition)
SECRET_KEY = os.getenv("SECRET_KEY")  # Clé de chiffrement (doit être une clé Fernet valide, générée via Fernet.generate_key())
try:
    CIPHER_KEY = (SECRET_KEY)
    cipher_suite = Fernet(CIPHER_KEY)  # Création du chiffreur Fernet pour protéger les mappings (caller <-> callee) contre l'exposition de données sensibles (OWASP)
except:
    raise ValueError("Clé SECRETS_KEY invalide")
def encrypt_mapping(mapping_dict: dict) -> str:
    """Chiffre un dictionnaire mapping caller <-> callee"""
    json_data = json.dumps(mapping_dict)
    return cipher_suite.encrypt(json_data.encode()).decode()
def decrypt_mapping(encrypted_str: str) -> dict:
    """Déchiffre un mapping chiffré"""
    json_data = cipher_suite.decrypt(encrypted_str.encode()).decode()
    return json.loads(json_data)
#------------------------------------ controle d'accees -------------------------------
def require_scope(required_scope: str):
    async def scope_checker(request: Request):
        # Vérifier la présence du token
        auth_header = request.headers.get("Authorization")
        if not auth_header or " " not in auth_header:
            raise HTTPException(status_code=401, detail="Token manquant ou invalide")

        token_str = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token_str, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expiré")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Token invalide")

        # Vérifier le scope
        if payload.get("scope") != required_scope:
            raise HTTPException(status_code=403, detail="Accès interdit")

        return payload

    return scope_checker
