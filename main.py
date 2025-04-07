# --- START OF FILE main.py ---

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import requests
import os
import json # Importar json
import base64
import logging
import traceback # Para errores de JWT
import sys # Para stderr
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# --- Importaciones específicas de Vonage para JWT ---
try:
    from vonage import Auth
except ImportError as e:
    print(f"FATAL: No se pudo importar 'vonage.Auth'. {e}", file=sys.stderr)
    print("Asegúrate de que el paquete 'vonage' (v4.x) esté instalado: pip install vonage", file=sys.stderr)
    exit(1)
# ----------------------------------------------------

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cargar variables de entorno
load_dotenv()
logger.info("Cargando variables de entorno desde .env...")

# --- Credenciales ---
# Para OAuth (SIM Swap)
VONAGE_CLIENT_ID = os.getenv("VONAGE_CLIENT_ID")
VONAGE_CLIENT_SECRET = os.getenv("VONAGE_CLIENT_SECRET")
# Para JWT (Messages API, etc.)
VONAGE_APPLICATION_ID = os.getenv("VONAGE_APPLICATION_ID")
VONAGE_PRIVATE_KEY_PATH = os.getenv("VONAGE_PRIVATE_KEY_PATH")
# Para APIs Legacy (SMS, NI Basic, etc.) - Si todavía se usan
VONAGE_API_KEY = os.getenv("VONAGE_API_KEY")
VONAGE_API_SECRET = os.getenv("VONAGE_API_SECRET")

# --- URLs de Vonage ---
# Base URLs (ajusta región si es necesario, ej., api-us.vonage.com)
VONAGE_OAUTH_URL = "https://api-eu.vonage.com/oauth2/token"
VONAGE_SIM_SWAP_URL = "https://api-eu.vonage.com/camara/sim-swap/v040/check"
# Base URL para APIs V1 (Messages API) - api.nexmo.com también suele funcionar
VONAGE_API_BASE_URL = "https://api.nexmo.com" # o https://api.vonage.com
VONAGE_MESSAGES_API_URL = f"{VONAGE_API_BASE_URL}/v1/messages"
# Base URL para APIs Legacy (Verify Legacy, SMS Legacy, NI Basic)
VONAGE_LEGACY_BASE_URL = "https://api.nexmo.com"

# --- ACL para JWT ---
# Define aquí los permisos que necesita tu JWT generado por esta app
# Coincide con los permisos de token_vonage.py por consistencia
# ¡¡AJUSTA ESTO A TUS NECESIDADES REALES!!
ACL_PATHS_FOR_JWT = {
    "paths": {
        "/v1/messages": {}, # Necesario para la API de Mensajes
        # Añade otras rutas necesarias aquí
    }
}
TOKEN_TTL_SECONDS = 3600 # 1 hora de vida para los tokens JWT

# --- Caché Simple en Memoria para Tokens ---
# Advertencia: Adecuado solo para despliegues de un solo worker. Usar Redis en producción.
_cached_oauth_token = None
_oauth_token_expiry_time = None
_cached_jwt = None
_jwt_expiry_time = None
_private_key_content = None # Cachear el contenido de la clave privada

def leer_clave_privada_para_jwt():
    """Lee y cachea el contenido del archivo de clave privada para JWT."""
    global _private_key_content
    if _private_key_content:
        return _private_key_content

    if not VONAGE_PRIVATE_KEY_PATH:
        logger.error("VONAGE_PRIVATE_KEY_PATH no está configurado en el entorno.")
        return None

    ruta_archivo = VONAGE_PRIVATE_KEY_PATH
    ruta_archivo_expandida = os.path.expanduser(ruta_archivo)
    # Si no es absoluta, buscar relativa al directorio de main.py
    if not os.path.isabs(ruta_archivo_expandida):
         script_dir = os.path.dirname(os.path.abspath(__file__))
         ruta_archivo_expandida = os.path.join(script_dir, ruta_archivo_expandida)

    try:
        with open(ruta_archivo_expandida, 'rb') as key_file:
            _private_key_content = key_file.read()
            logger.info(f"Clave privada para JWT leída y cacheada desde '{ruta_archivo_expandida}'")
            return _private_key_content
    except FileNotFoundError:
        logger.error(f"No se encontró el archivo de clave privada para JWT en: '{ruta_archivo_expandida}'")
        return None
    except Exception as e:
        logger.error(f"Error inesperado al leer la clave privada para JWT: {e}")
        traceback.print_exc()
        return None

def get_vonage_jwt():
    """
    Genera o recupera un JWT cacheado de Vonage para APIs como Messages.
    """
    global _cached_jwt, _jwt_expiry_time

    now = datetime.now()
    # Revisa caché (con buffer de 60 seg)
    if _cached_jwt and _jwt_expiry_time and now < (_jwt_expiry_time - timedelta(seconds=60)):
        logger.info("Usando JWT de Vonage cacheado.")
        return _cached_jwt

    logger.info("Generando nuevo JWT de Vonage...")
    if not VONAGE_APPLICATION_ID:
        logger.error("VONAGE_APPLICATION_ID no configurado para generar JWT.")
        raise HTTPException(status_code=500, detail="Configuración de servidor incompleta (JWT App ID).")

    private_key = leer_clave_privada_para_jwt()
    if not private_key:
        raise HTTPException(status_code=500, detail="No se pudo leer la clave privada para generar JWT.")

    try:
        auth_instance = Auth(
            application_id=VONAGE_APPLICATION_ID,
            private_key=private_key
        )
        jwt_params_for_method = {
             'acl': ACL_PATHS_FOR_JWT, # Usar la ACL definida globalmente
             'ttl': TOKEN_TTL_SECONDS # Usar el TTL entero definido globalmente
        }
        token_bytes = auth_instance.generate_application_jwt(jwt_params_for_method)
        jwt_token = token_bytes.decode('utf-8')

        _cached_jwt = jwt_token
        _jwt_expiry_time = now + timedelta(seconds=TOKEN_TTL_SECONDS)
        logger.info(f"Nuevo JWT de Vonage generado y cacheado. Expira alrededor de: {_jwt_expiry_time}")
        return jwt_token

    except Exception as e:
        logger.error(f"Fallo al generar el JWT de Vonage: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error interno al generar el token JWT: {e}")

def get_vonage_oauth_token():
    """
    Obtiene un token OAuth de Vonage usando client credentials (para SIM Swap).
    Usa caché simple en memoria.
    """
    global _cached_oauth_token, _oauth_token_expiry_time

    now = datetime.now()
    if _cached_oauth_token and _oauth_token_expiry_time and now < (_oauth_token_expiry_time - timedelta(seconds=60)):
        logger.info("Usando token OAuth de Vonage cacheado.")
        return _cached_oauth_token

    logger.info("Obteniendo nuevo token OAuth de Vonage...")
    if not VONAGE_CLIENT_ID or not VONAGE_CLIENT_SECRET:
         logger.error("VONAGE_CLIENT_ID o VONAGE_CLIENT_SECRET no configurados.")
         raise HTTPException(status_code=500, detail="Configuración de servidor incompleta (OAuth).")

    credentials = f"{VONAGE_CLIENT_ID}:{VONAGE_CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode("ascii")).decode("ascii")

    headers = {"Authorization": f"Basic {encoded_credentials}", "Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "client_credentials", "scope": "sim-swap:check"} # Asegúrate que este scope está habilitado

    try:
        response = requests.post(VONAGE_OAUTH_URL, headers=headers, data=data)
        logger.info(f"Estado de solicitud de token OAuth: {response.status_code}")
        response.raise_for_status()

        token_data = response.json()
        token = token_data.get("access_token")
        expires_in = token_data.get("expires_in")

        if not token:
            logger.error("Token de acceso no encontrado en la respuesta OAuth.")
            raise HTTPException(status_code=500, detail="Fallo al obtener token de acceso de Vonage.")

        _cached_oauth_token = token
        if expires_in:
            _oauth_token_expiry_time = now + timedelta(seconds=int(expires_in))
            logger.info(f"Nuevo token OAuth cacheado. Expira alrededor de: {_oauth_token_expiry_time}")
        else:
             _oauth_token_expiry_time = now + timedelta(hours=1)
             logger.warning("OAuth 'expires_in' no encontrado, asumiendo validez de 1 hora.")

        logger.info("Token OAuth de Vonage obtenido y cacheado exitosamente.")
        return token

    except requests.exceptions.RequestException as e:
        logger.error(f"Error solicitando token OAuth de Vonage: {e}")
        raise HTTPException(status_code=503, detail=f"No se pudo conectar al servicio de autenticación de Vonage: {e}")
    except Exception as e:
        logger.error(f"Error procesando respuesta de token OAuth de Vonage: {e}")
        if 'response' in locals() and response is not None:
             logger.error(f"Estado respuesta: {response.status_code}, Texto respuesta: {response.text}")
        raise HTTPException(status_code=500, detail=f"Error procesando respuesta de autenticación de Vonage: {e}")

# --- FastAPI App ---
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Restringir en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PhoneNumberRequest(BaseModel):
    phone_number: str
    location_zone: str = ""

def log_action(action: str):
    """Log action."""
    log_message = f"{datetime.now().isoformat()} - {action}"
    logger.info(log_message)
    try:
        with open("spy_logs.txt", "a") as log_file:
            log_file.write(f"{log_message}\n")
    except IOError as e:
        logger.error(f"Failed to write to spy_logs.txt: {e}")

# --- Endpoints ---

@app.post("/check_sim_swap")
async def check_sim_swap(request: Request):
    """
    Verifica SIM swap usando Vonage CAMARA API (requiere OAuth Token).
    """
    try:
        body = await request.json()
        phone_number = body.get("phone_number")
        if not phone_number:
            raise HTTPException(status_code=400, detail="Falta número de teléfono.")

        # --- Usa OAuth Token ---
        access_token = get_vonage_oauth_token()
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        payload = {"phoneNumber": phone_number, "maxAge": 240} # Asegúrate E.164

        logger.info(f"Verificando SIM Swap para {phone_number}...")
        response = requests.post(VONAGE_SIM_SWAP_URL, headers=headers, json=payload)
        logger.info(f"SIM Swap API Status: {response.status_code}")
        logger.debug(f"SIM Swap API Response: {response.text}")

        if response.status_code == 401:
             global _cached_oauth_token, _oauth_token_expiry_time
             _cached_oauth_token = None; _oauth_token_expiry_time = None
             logger.warning("401 de SIM Swap API, limpiando caché de token OAuth.")
        response.raise_for_status()

        data = response.json()
        swapped_result = data.get('swapped', 'N/A')
        log_action(f"SIM Swap Check for {phone_number}: Result={swapped_result}")
        return {"message": f"Verificación SIM swap exitosa.", "result": data}

    except requests.exceptions.RequestException as e:
        logger.error(f"Error contactando Vonage SIM Swap API: {e}")
        log_action(f"SIM Swap Check for {phone_number}: Failed (Network Error)")
        raise HTTPException(status_code=503, detail=f"Error contactando Vonage SIM Swap API: {e}")
    except HTTPException as e:
        if 'phone_number' in locals() and phone_number: log_action(f"SIM Swap Check for {phone_number}: Failed (HTTP {e.status_code})")
        raise e
    except Exception as e:
        logger.error(f"Error inesperado en /check_sim_swap: {e}", exc_info=True)
        if 'phone_number' in locals() and phone_number: log_action(f"SIM Swap Check for {phone_number}: Failed (Internal Server Error)")
        raise HTTPException(status_code=500, detail="Error interno del servidor durante verificación SIM swap.")

@app.post("/send_mission_alert")
async def send_mission_alert(request: Request):
    """
    Envía alerta SMS usando Vonage Messages API v1 (requiere JWT).
    """
    try:
        body = await request.json()
        phone_number = body.get("phone_number")
        if not phone_number:
            raise HTTPException(status_code=400, detail="Falta número de teléfono.")

        # --- Usa JWT ---
        jwt_token = get_vonage_jwt()
        headers = {"Authorization": f"Bearer {jwt_token}", "Content-Type": "application/json"}
        payload = {
            "message_type": "text",
            "channel": "sms",
            "to": phone_number, # Asegúrate E.164
            "from": "SpyHQ", # Debe ser un número de Vonage o Sender ID aprobado
            "text": "Agent Alert: Target’s SIM card status requires attention. Investigate immediately."
        }

        logger.info(f"Enviando alerta SMS (via Messages API) a {phone_number}...")
        response = requests.post(VONAGE_MESSAGES_API_URL, headers=headers, json=payload)
        logger.info(f"Messages API Status Code: {response.status_code}")
        logger.debug(f"Messages API Response Text: {response.text}")

        # El manejo de errores puede variar con Messages API
        # 202 Accepted suele ser éxito para envío
        if response.status_code == 202:
            data = response.json()
            message_uuid = data.get("message_uuid")
            log_action(f"Mission Alert (Messages API) enqueued to {phone_number}: Success (UUID: {message_uuid})")
            return {"message": "Alerta de misión enviada exitosamente!", "details": data}
        elif response.status_code == 401:
             global _cached_jwt, _jwt_expiry_time
             _cached_jwt = None; _jwt_expiry_time = None
             logger.warning("401 de Messages API, limpiando caché de JWT.")
             response.raise_for_status() # Reintentar podría ser una opción
        else:
            # Otros errores (4xx, 5xx)
             log_action(f"Mission Alert (Messages API) to {phone_number}: Failed (HTTP {response.status_code})")
             try:
                 error_data = response.json()
                 logger.error(f"Messages API Error: {error_data}")
                 # Intenta mostrar un error útil si está disponible
                 detail = error_data.get('title', 'Unknown Messages API Error')
                 if 'detail' in error_data: detail += f" - {error_data['detail']}"
                 raise HTTPException(status_code=response.status_code, detail=detail)
             except ValueError: # Si la respuesta de error no es JSON
                 response.raise_for_status() # Dejar que requests maneje el error HTTP


    except requests.exceptions.RequestException as e:
        logger.error(f"Error contactando Vonage Messages API: {e}")
        log_action(f"Mission Alert (Messages API) to {phone_number}: Failed (Network Error)")
        raise HTTPException(status_code=503, detail=f"Error contactando Vonage Messages API: {e}")
    except HTTPException as e:
        # Si ya es HTTPException (incluyendo las generadas por errores API), regístrala si aún no se hizo y relanza
        if 'phone_number' in locals() and phone_number and not action_logged(f"Mission Alert (Messages API) to {phone_number}: Failed"):
             log_action(f"Mission Alert (Messages API) to {phone_number}: Failed (HTTP {e.status_code})")
        raise e
    except Exception as e:
        logger.error(f"Error inesperado en /send_mission_alert: {e}", exc_info=True)
        if 'phone_number' in locals() and phone_number: log_action(f"Mission Alert (Messages API) to {phone_number}: Failed (Internal Server Error)")
        raise HTTPException(status_code=500, detail="Error interno del servidor durante envío de alerta.")

# Helper para evitar doble log en HTTPException
_logged_actions_this_request = set() # Muy simple, podría necesitar contexto de request real
def action_logged(action_key):
    # Basic check, might need improvement in real async context
    # This is just to prevent double logging when re-raising HTTPExceptions
    if action_key in _logged_actions_this_request:
        return True
    _logged_actions_this_request.add(action_key)
    # Clear periodically or based on request context if needed
    return False


# --- Endpoints Legacy (Usan API Key/Secret) ---
# Estos se mantienen como estaban, usando las URLs legacy y autenticación básica.
# NOTA: Verifica si estos endpoints existen realmente o si son ficticios.

@app.post("/verify_location")
def verify_location(request: PhoneNumberRequest):
    """Verifica ubicación (Usa API Key/Secret - Endpoint posiblemente ficticio)."""
    url = f"{VONAGE_LEGACY_BASE_URL}/verify/location/{request.phone_number}" # Ficticio?
    logger.info(f"Verificando ubicación (Legacy) para {request.phone_number}")
    if not VONAGE_API_KEY or not VONAGE_API_SECRET:
        raise HTTPException(status_code=500, detail="Legacy API Key/Secret no configurados.")
    try:
        response = requests.get(url, auth=(VONAGE_API_KEY, VONAGE_API_SECRET))
        response.raise_for_status()
        data = response.json()
        result = "Target located..." # Lógica original...
        log_action(f"Location Check (Legacy) for {request.phone_number}: {result}")
        return {"message": result, "details": data}
    except requests.exceptions.RequestException as e:
         logger.error(f"Error en /verify_location (Legacy): {e}")
         log_action(f"Location Check (Legacy) for {request.phone_number}: Failed (Network Error)")
         raise HTTPException(status_code=503, detail=f"Error contactando Vonage (Legacy): {e}")
    except Exception as e:
        logger.error(f"Error procesando /verify_location (Legacy): {e}", exc_info=True)
        log_action(f"Location Check (Legacy) for {request.phone_number}: Failed (Processing Error)")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")

@app.post("/retrieve_last_location")
def retrieve_last_location(request: PhoneNumberRequest):
    """Obtiene última ubicación (Usa API Key/Secret - Endpoint posiblemente ficticio)."""
    url = f"{VONAGE_LEGACY_BASE_URL}/verify/device_location/{request.phone_number}" # Ficticio?
    logger.info(f"Obteniendo última ubicación (Legacy) para {request.phone_number}")
    if not VONAGE_API_KEY or not VONAGE_API_SECRET:
        raise HTTPException(status_code=500, detail="Legacy API Key/Secret no configurados.")
    try:
        response = requests.get(url, auth=(VONAGE_API_KEY, VONAGE_API_SECRET))
        response.raise_for_status()
        data = response.json()
        result = f"Last known location retrieved..." # Lógica original...
        log_action(f"Location Retrieval (Legacy) for {request.phone_number}: {result}")
        return {"message": result, "details": data}
    except requests.exceptions.RequestException as e:
         logger.error(f"Error en /retrieve_last_location (Legacy): {e}")
         log_action(f"Location Retrieval (Legacy) for {request.phone_number}: Failed (Network Error)")
         raise HTTPException(status_code=503, detail=f"Error contactando Vonage (Legacy): {e}")
    except Exception as e:
        logger.error(f"Error procesando /retrieve_last_location (Legacy): {e}", exc_info=True)
        log_action(f"Location Retrieval (Legacy) for {request.phone_number}: Failed (Processing Error)")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")

@app.post("/verify_number")
def verify_number(request: PhoneNumberRequest):
    """Verifica número usando Number Insight Basic (Usa API Key/Secret)."""
    url = f"{VONAGE_LEGACY_BASE_URL}/ni/basic/json"
    logger.info(f"Verificando número (NI Basic) {request.phone_number}")
    if not VONAGE_API_KEY or not VONAGE_API_SECRET:
        raise HTTPException(status_code=500, detail="Legacy API Key/Secret no configurados.")
    params = {"api_key": VONAGE_API_KEY, "api_secret": VONAGE_API_SECRET, "number": request.phone_number}
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        is_valid = data.get("status") == 0 # NI Basic status 0 is success
        result = "Número verificado!" if is_valid else "Número inválido o inactivo."
        log_action(f"Number Verification (NI Basic) for {request.phone_number}: {result}")
        return {"message": result, "valid": is_valid, "details": data}
    except requests.exceptions.RequestException as e:
         logger.error(f"Error en /verify_number (NI Basic): {e}")
         log_action(f"Number Verification (NI Basic) for {request.phone_number}: Failed (Network Error)")
         raise HTTPException(status_code=503, detail=f"Error contactando Vonage NI API: {e}")
    except Exception as e:
        logger.error(f"Error procesando /verify_number (NI Basic): {e}", exc_info=True)
        log_action(f"Number Verification (NI Basic) for {request.phone_number}: Failed (Processing Error)")
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")

@app.get("/logs")
def get_logs():
    """Obtiene el contenido del archivo de logs."""
    try:
        with open("spy_logs.txt", "r") as log_file:
            lines = log_file.readlines()
            logs = lines[-100:] # Últimas 100 líneas
        return {"logs": logs}
    except FileNotFoundError:
        logger.info("Archivo 'spy_logs.txt' no encontrado.")
        return {"logs": [], "message": "Archivo de logs no encontrado."}
    except Exception as e:
        logger.error(f"Error leyendo archivo de logs: {e}")
        raise HTTPException(status_code=500, detail="No se pudo leer el archivo de logs.")

# --- Startup ---
if __name__ == "__main__":
    # Verificar credenciales esenciales al inicio
    essential_configs_missing = []
    if not VONAGE_CLIENT_ID or not VONAGE_CLIENT_SECRET:
        essential_configs_missing.append("OAuth (Client ID/Secret)")
    if not VONAGE_APPLICATION_ID or not VONAGE_PRIVATE_KEY_PATH:
        essential_configs_missing.append("JWT (App ID/Private Key Path)")
    # Legacy keys son opcionales si solo usas SIM Swap y Messages
    if not VONAGE_API_KEY or not VONAGE_API_SECRET:
        logger.warning("VONAGE_API_KEY o VONAGE_API_SECRET no encontrados. Endpoints legacy fallarán.")

    if essential_configs_missing:
        logger.error(f"Configuración esencial faltante en variables de entorno o .env: {', '.join(essential_configs_missing)}")
        logger.error("La aplicación no puede funcionar correctamente. Saliendo.")
        exit(1)
    else:
        # Intentar leer la clave privada al inicio para detectar errores temprano
        if not leer_clave_privada_para_jwt():
             logger.error("Fallo al leer la clave privada para JWT al inicio. Verifica VONAGE_PRIVATE_KEY_PATH.")
             # Decide si salir o continuar (JWT fallará después)
             exit(1)


    logger.info("Iniciando Servicio Backend Spy Network...")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# --- END OF FILE main.py ---