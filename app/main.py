from fastapi import FastAPI, HTTPException, Body, Depends, Request #framework pour créer l'API REST, HTTPException pour erreurs
import psycopg2 #connexion à PostgreSQL
from dotenv import load_dotenv #charger les variables d'environnement depuis .env
import os
from faker import Faker #générer des données fictives (numéros proxy)
import uuid #générer des identifiants uniques pour les appels
#-------logs
from datetime import datetime, timedelta #gérer l'expiration des proxies
#-------simulation
import threading  # Pour simulation en background
import time  # Pour délais simulés
import random  # Pour résultats aléatoires
import logging  # Pour journaliser les erreurs internes sans les exposer
#------- rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.responses import JSONResponse



#----------------------------------------------- Importer toutes les fonctions de securite.py ----------------------------------------------------------------------------------

from securite import (
    create_jwt_token,jwt_required,verify_password,encrypt_mapping,LoginRequest,MaskRequest,require_scope
)
#----------------------- Charger les variables d'environnement depuis le fichier .env ------------------------------------------
load_dotenv()
#------------------------------ Création de l'application FastAPI ---------------------------------------------

app = FastAPI(
    title="API Masquage Appels - Tunisie Telecom PFE",
    version="1.0.0"
)
#------------------------------------------implementer le rate limiting --------------------

# Initialiser le limiter (basé sur l'IP pour simplicité ; ajustable pour JWT si besoin)
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])  # 100 req/min pendant dev ; ajustez à 10/minute en prod

#middleware fourni par SlowAPI sert a vérifier à chaque requête si l’utilisateur (ou IP) a dépassé le quota de requêtes autorisées.
app.add_middleware(SlowAPIMiddleware)
# Attacher le Limiter à l'état de l'application
app.state.limiter = limiter
# Gestionnaire d'erreur personnalisé (évite l'exposition de détails)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(RateLimitExceeded)
async def ratelimit_handler(request: Request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Trop de requêtes. Veuillez réessayer plus tard."}
    )


#----------------------------------------  Connexion à la base de données PostgreSQL  -----------------------------------

def get_db_connection():
    return psycopg2.connect(os.getenv('DATABASE_URL'))

#-----------------------Initialisation de Faker (pour générer des numéros fictifs) ------------------------

fake = Faker()
   
#----------------------------- Endpoint de test de santé (Vérifie si l’API est opérationnelle et si la connexion à la base est possible --------------------------------

@app.get("/health")
def health():
  return {"status": "API prête ! Pool DB connecté."}

#-------------------------------- authentification JWT  -----------------------------------
 

@app.post("/auth/login")
@limiter.limit("5/minute")

async def login(request: Request, credentials: LoginRequest = Body(...)):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        username = credentials.username
        password = credentials.password
        logging.debug(f"Connexion à la DB OK. Username recherché : {username}")

        cur.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        logging.debug(f"Résultat SQL : {result}")

        cur.close()
        conn.close()

        if result and verify_password(password, result[0]):
            token = create_jwt_token(username)
            logging.debug(f"Token créé pour {username}")
            return {"access_token": token, "token_type": "bearer"}
        
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    except HTTPException:
        raise

    except Exception as e:
        logging.exception("Erreur dans /auth/login")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")


#---------------------------- Endpoint : Statut du pool de numéros proxy --------------------------------

@app.get("/pool/status")
@limiter.limit("2/minute")
async def pool_status(request: Request, token: dict = Depends(require_scope("admin"))):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Compter les numéros disponibles
        cur.execute("SELECT COUNT(*) FROM proxy_pool WHERE status = 'available';")
        available = cur.fetchone()[0]
        # Compter le total de numéros
        cur.execute("SELECT COUNT(*) FROM proxy_pool;")
        total = cur.fetchone()[0]
        #connexion a bd
        cur.close()
        conn.close()
        # Calcul du pourcentage d’utilisation du pool
        usage = ((total - available) / total * 100) if total > 0 else 0
        #resultat de requete
        return {
            "total_proxies": total,
            "available_proxies": available,
            "usage_percent": f"{usage:.1f}%",
            "message": "Pool fictif pour simulation de masquage d'appels"
        }
    #capturer les erreurs survenant pendant l’exécution du code et retournent une réponse HTTP 500 avec un message expliquant la cause de l’erreur
    except Exception as e:
        logging.error(f"Erreur interne dans /pool/status : {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")
#---------------------------------- Endpoint principal : Masquage d’un appel  -------------------------------------

@app.post("/mask/call")
@limiter.limit("10/minute")  # Limite stricte pour cet endpoint
async def mask_call(request: Request, body: MaskRequest = Body(...), token: str = Depends(jwt_required)):    
    caller_real = body.caller_real
    callee_real = body.callee_real

    try:
        # Connexion à la base
        conn = get_db_connection()
        cur = conn.cursor()

        # Chercher un numéro proxy disponible de manière aléatoire
        cur.execute(""" SELECT proxy_number FROM proxy_pool WHERE status = 'available'ORDER BY RANDOM() LIMIT 1;""")
        result = cur.fetchone()

        # Si aucun numéro disponible, en créer un nouveau fictif
        if not result:
            new_proxy = f"+21600{fake.random_number(digits=6):06d}"
            cur.execute(
                "INSERT INTO proxy_pool (proxy_number, status) VALUES (%s, 'available') RETURNING proxy_number;",
                (new_proxy,)
            )
            new_result = cur.fetchone()
            if new_result:
                proxy = new_result[0]
            else:
                cur.close()
                conn.close()
                raise HTTPException(status_code=503, detail="Échec de génération du numéro proxy")
        else:
            proxy = result[0]

        # Création du mapping chiffré entre appelant et appelé
        mapping = {"caller_real": body.caller_real, "callee_real": body.callee_real}        
        encrypted_mapping = encrypt_mapping(mapping)

        # Génération d’un ID d’appel unique
        call_id = str(uuid.uuid4())

        # Date d’expiration (le proxy est valide 24h)
        expires_at = datetime.now() + timedelta(hours=24)

        # Mettre à jour le proxy dans la base : assignation à un appel
        cur.execute("""
            UPDATE proxy_pool 
            SET status = 'assigned',assigned_to = %s,call_id = %s,expires_at = %s WHERE proxy_number = %s RETURNING id;
        """, (encrypted_mapping, call_id, expires_at, proxy))

        conn.commit()
        cur.close()
        conn.close()
       
        # Simulation d'Appel en Background
        def simulate_call(proxy, call_id):
            events = ["RINGING", "ANSWERED", "HANGUP"]
            for event in events:
                time.sleep(random.uniform(1, 3))
                status = "SUCCESS" if random.random() > 0.1 else "FAILED (busy)"
                print(f"Simulation: {event} - {status}")

        logging.info(f"Appel masqué : call_id={call_id}, proxy={proxy}, utilisateur={token['sub'] if 'sub' in token else 'inconnu'}")  # Log sécurisé pour monitoring        

        threading.Thread(target=simulate_call, args=(proxy, call_id)).start()

        # Réponse envoyée à l’utilisateur
        return {
            "success": True,
            "call_id": call_id,
            "proxy_number": proxy,
            "expires_at": expires_at.isoformat(),
            "message": "Numéro réel masqué par proxy (simulation)"
        }

    except Exception as e:
        logging.error(f"Erreur interne dans /mask/call : {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

