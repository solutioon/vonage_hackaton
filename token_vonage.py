# --- START OF FILE token_vonage.py ---
import os
import json
from datetime import timedelta
from dotenv import load_dotenv
import traceback
import sys

try:
    from vonage import Auth
except ImportError as e:
    print(f"Error: No se pudo importar desde los paquetes de Vonage: {e}", file=sys.stderr)
    print("Asegúrate de que el paquete 'vonage' (v4.x) esté instalado correctamente.", file=sys.stderr)
    print("Intenta reinstalar: pip uninstall vonage -y && pip install vonage --force-reinstall --no-cache-dir", file=sys.stderr)
    exit(1)

load_dotenv()

# --- Configuración ---
# Asegúrate de que estas variables están en tu .env
APP_ID = os.environ.get("VONAGE_APPLICATION_ID", "TU_ID_DE_APLICACION_AQUI")
PRIVATE_KEY_PATH = os.environ.get("VONAGE_PRIVATE_KEY_PATH", "/ruta/completa/a/tu/private.key")
TOKEN_TTL_SECONDS = int(os.environ.get("VONAGE_TOKEN_TTL", 3600)) # 1 hora por defecto

# --- ACL (Access Control List) ---
# DEFINE AQUÍ LOS PERMISOS QUE REALMENTE NECESITAS PARA TU JWT
# '/v1/messages' es para la API de Mensajes (Enviar/Recibir SMS, WhatsApp, etc.)
# '/*/users/**' y '/*/conversations/**' son para la API de Conversaciones (si la usas)
# Consulta la documentación de cada API para las rutas específicas que necesitas.
ACL_PATHS = {
    "paths": {
        # --- API de Mensajes ---
        "/v1/messages": {}, # Necesario para enviar SMS/WhatsApp/etc. via Messages API

        # --- API de Despacho (Dispatch API) ---
        # "/v1/dispatch": {},

        # --- API de Conversaciones (si se usa) ---
        # "/*/users/**": {},
        # "/*/conversations/**": {},
        # "/*/sessions/**": {},
        # "/*/devices/**": {},
        # "/*/media/**": {},
        # "/*/applications/**": {},
        # "/*/push/**": {},
        # "/*/knocking/**": {},
        # "/*/legs/**": {},

        # --- API de Voz (si se usa con JWT) ---
        # "/v1/calls": {},
        # "/*/calls/**": {},

        # --- API de Video (si se usa con JWT) ---
        # "/v1/meetings/**": {}, # Ejemplo, verifica rutas reales

        # --- Number Insight v2 (si se usa con JWT) ---
        # "/v1/ni": {},

        # --- Verify v2 (si se usa con JWT) ---
        # "/v2/verify": {},
    }
}
# --- Lógica del Script ---

def leer_clave_privada(ruta_archivo):
    """Lee el contenido del archivo de clave privada."""
    ruta_archivo_expandida = os.path.expanduser(ruta_archivo)
    if not os.path.isabs(ruta_archivo_expandida):
         # Asegurarse de obtener la ruta absoluta del directorio del script
         script_dir = os.path.dirname(os.path.abspath(__file__))
         ruta_archivo_expandida = os.path.join(script_dir, ruta_archivo_expandida)

    try:
        with open(ruta_archivo_expandida, 'rb') as key_file:
            private_key = key_file.read()
            print(f"INFO: Clave privada leída correctamente desde '{ruta_archivo_expandida}'")
            return private_key
    except FileNotFoundError:
        print(f"ERROR: No se encontró el archivo de clave privada en la ruta: '{ruta_archivo_expandida}'", file=sys.stderr)
        print(f"       (Ruta original: '{ruta_archivo}')", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: Ocurrió un error inesperado al leer el archivo de clave privada: {e}", file=sys.stderr)
        traceback.print_exc()
        return None

def generar_jwt_vonage(app_id, private_key_content, acl, ttl_seconds_int):
    """Genera el JWT creando una instancia de Auth y llamando a su método."""
    if not app_id or app_id == "TU_ID_DE_APLICACION_AQUI":
        print("ERROR: Falta el ID de Aplicación Vonage (VONAGE_APPLICATION_ID).", file=sys.stderr)
        return None
    if not private_key_content:
        return None

    print("INFO: Intentando generar JWT creando instancia de Auth...")
    try:
        auth_instance = Auth(
            application_id=app_id,
            private_key=private_key_content
        )
        jwt_params_for_method = {
             'acl': acl,
             'ttl': ttl_seconds_int
        }
        token_bytes = auth_instance.generate_application_jwt(jwt_params_for_method)
        print("INFO: JWT generado internamente (como bytes).")
        return token_bytes.decode('utf-8')
    except TypeError as te:
         print(f"ERROR: TypeError al interactuar con Auth: {te}", file=sys.stderr)
         traceback.print_exc()
         return None
    except Exception as e:
        print(f"ERROR: Fallo inesperado al generar el JWT: {e}", file=sys.stderr)
        traceback.print_exc()
        return None

if __name__ == "__main__":
    print("--- Iniciando generación de token JWT de Vonage (SDK v4.x) ---")
    if APP_ID == "TU_ID_DE_APLICACION_AQUI":
        print("ERROR: VONAGE_APPLICATION_ID no está configurado en el entorno o .env", file=sys.stderr)
        exit(1)
    if PRIVATE_KEY_PATH == "/ruta/completa/a/tu/private.key":
        print("ERROR: VONAGE_PRIVATE_KEY_PATH no está configurado en el entorno o .env", file=sys.stderr)
        exit(1)

    print(f"Usando Application ID: {APP_ID}")
    print(f"Buscando Private Key en: {PRIVATE_KEY_PATH}")
    print(f"ACL definida: {json.dumps(ACL_PATHS, indent=2)}")
    print(f"TTL del token: {TOKEN_TTL_SECONDS} segundos ({TOKEN_TTL_SECONDS/3600:.1f} horas)")
    print("-" * 40)

    clave_privada = leer_clave_privada(PRIVATE_KEY_PATH)

    if clave_privada:
        jwt_token = generar_jwt_vonage(APP_ID, clave_privada, ACL_PATHS, TOKEN_TTL_SECONDS)

        if jwt_token:
            print("\n" + "=" * 40)
            print("¡TOKEN JWT GENERADO CON ÉXITO!")
            print("=" * 40 + "\n")
            print(jwt_token)
            print("\n" + "=" * 40)
            print("Puedes usar este token en la cabecera 'Authorization':")
            print("Authorization: Bearer <token_jwt_generado>")
            print("=" * 40)
        else:
            print("\n" + "!" * 40, file=sys.stderr)
            print("ERROR: No se pudo generar el token JWT.", file=sys.stderr)
            print("!" * 40, file=sys.stderr)
    else:
        print("\n" + "!" * 40, file=sys.stderr)
        print("ERROR: No se pudo leer la clave privada.", file=sys.stderr)
        print("!" * 40, file=sys.stderr)

    print("\n--- Fin del script ---")
# --- END OF FILE token_vonage.py ---