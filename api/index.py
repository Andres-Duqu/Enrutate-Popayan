import os
import datetime
import hashlib
import hmac
from flask import Flask, jsonify, request
from flask_cors import CORS
from supabase import create_client
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------------------------
# CONEXIÓN A SUPABASE
# ------------------------------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "enrutate_jwt_secret_popayan_2026_default")

supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Error conectando a Supabase: {e}")


def _check_pw(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    if plain == hashed:
        return True
    if hashed.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(hashed, plain)
        except Exception:
            pass
    if len(hashed) == 64:
        legacy = hashlib.sha256(plain.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, hashed)
    return False


def _get_user_by_username(username: str):
    if not supabase:
        return None
    for table_name in ["usuarios_api", "users", "usuarios"]:
        try:
            res = supabase.table(table_name).select("*").eq("username", username).execute()
            if res.data and len(res.data) > 0:
                user = res.data[0]
                user["_table"] = table_name
                return user
        except Exception:
            continue
    return None


def _create_jwt(user: dict) -> str:
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    payload = {
        "sub": str(user.get("id", 1)),
        "username": user.get("username", ""),
        "role": user.get("role", "USUARIO"),
        "full_name": user.get("full_name", user.get("username", "")),
        "exp": exp
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


# ==============================================================================
# RUTAS DE AUTENTICACIÓN (LOGIN, REGISTRO, PERFIL)
# ==============================================================================

@app.route("/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
@app.route("/api/servicio_monitoreo/login", methods=["POST"])
def login():
    if not supabase:
        return jsonify({
            "success": False,
            "error": "Base de datos no configurada",
            "mensaje": "Verifica las variables SUPABASE_URL y SUPABASE_KEY en Vercel."
        }), 500

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Campos requeridos",
            "mensaje": "Debe ingresar usuario y contraseña."
        }), 400

    user = _get_user_by_username(username)
    if not user or not _check_pw(password, user.get("password_hash", "")):
        return jsonify({
            "success": False,
            "error": "Credenciales inválidas",
            "mensaje": "Usuario o contraseña incorrectos."
        }), 401

    token = _create_jwt(user)
    return jsonify({
        "success": True,
        "token": token,
        "tipo": "Bearer",
        "username": user.get("username"),
        "role": user.get("role", "USUARIO"),
        "full_name": user.get("full_name", user.get("username")),
        "api_key": user.get("api_key", "")
    }), 200


@app.route("/register", methods=["POST"])
@app.route("/api/register", methods=["POST"])
@app.route("/api/servicio_monitoreo/register", methods=["POST"])
def register():
    if not supabase:
        return jsonify({
            "success": False,
            "error": "Base de datos no configurada",
            "mensaje": "Verifica las variables SUPABASE_URL y SUPABASE_KEY en Vercel."
        }), 500

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Campos requeridos",
            "mensaje": "Debe enviar usuario y contraseña."
        }), 400

    if len(password) < 6:
        return jsonify({
            "success": False,
            "error": "Contraseña muy corta",
            "mensaje": "La contraseña debe tener al menos 6 caracteres."
        }), 400

    if _get_user_by_username(username):
        return jsonify({
            "success": False,
            "error": "Usuario duplicado",
            "mensaje": f"El usuario '{username}' ya está registrado."
        }), 409

    hashed = generate_password_hash(password)
    target_table = "usuarios_api"

    new_user = {
        "username": username,
        "password_hash": hashed,
        "full_name": f"Usuario {username.capitalize()}",
        "role": "USUARIO"
    }

    try:
        res = supabase.table(target_table).insert(new_user).execute()
        created = res.data[0] if res.data else new_user
    except Exception as e:
        # Intenta en tabla users si usuarios_api falla
        try:
            target_table = "users"
            res = supabase.table(target_table).insert(new_user).execute()
            created = res.data[0] if res.data else new_user
        except Exception as e2:
            return jsonify({
                "success": False,
                "error": "Error al registrar",
                "mensaje": str(e2)
            }), 500

    token = _create_jwt(created)
    return jsonify({
        "success": True,
        "token": token,
        "username": username,
        "role": "USUARIO",
        "mensaje": "Usuario registrado exitosamente."
    }), 201


@app.route("/me", methods=["GET"])
@app.route("/api/me", methods=["GET"])
@app.route("/api/servicio_monitoreo/me", methods=["GET"])
def me():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "No autorizado"}), 401

    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({
            "success": True,
            "username": payload.get("username"),
            "role": payload.get("role"),
            "full_name": payload.get("full_name")
        })
    except Exception:
        return jsonify({"error": "Token inválido o expirado"}), 401


# ==============================================================================
# RUTAS DE TRANSPORTE Y OPERACIONES
# ==============================================================================

@app.route("/rutas", methods=["GET"])
@app.route("/api/rutas", methods=["GET"])
def listar_rutas():
    if not supabase:
        return jsonify([]), 200
    for tbl in ["rutas", "routes"]:
        try:
            res = supabase.table(tbl).select("*").execute()
            if res.data:
                return jsonify(res.data), 200
        except Exception:
            continue
    return jsonify([]), 200


@app.route("/paradas", methods=["GET"])
@app.route("/api/paradas", methods=["GET"])
def listar_paradas():
    if not supabase:
        return jsonify([]), 200
    for tbl in ["paradas", "stops"]:
        try:
            res = supabase.table(tbl).select("*").execute()
            if res.data:
                return jsonify(res.data), 200
        except Exception:
            continue
    return jsonify([]), 200


# ==============================================================================
# COMPATIBILIDAD CON LA GUÍA (TAREAS)
# ==============================================================================

@app.route("/tareas", methods=["GET"])
@app.route("/api/tareas", methods=["GET"])
def listar_tareas():
    if not supabase:
        return jsonify([]), 200
    try:
        res = supabase.table("tareas").select("*").order("id").execute()
        return jsonify(res.data or []), 200
    except Exception:
        return jsonify([]), 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return jsonify({
        "servicio": "EnRutate Popayán API Gateway",
        "status": "online",
        "supabase": bool(supabase),
        "path": path
    }), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)

