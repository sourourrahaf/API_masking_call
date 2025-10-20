from main import app  # ou from app.main import app si ton main.py est dans un dossier "app"
import uvicorn
import os
from dotenv import load_dotenv

# Charger les variables d'environnement depuis .env
load_dotenv()

if __name__ == "__main__":
    # Récupérer les chemins depuis .env
    certfile = os.getenv("SSL_CERTFILE")
    keyfile = os.getenv("SSL_KEYFILE")

    # Lancer Uvicorn avec HTTPS
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        log_level="info"
    )
