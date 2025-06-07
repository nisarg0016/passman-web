import sqlEnd
import pyotp
import qrcode
import io
import base64
import jwt
from datetime import datetime, timedelta
from passlib.hash import bcrypt
import os

SECRET_KEY = os.getenv("SECRET_KEY")

def isUser(username):
    """Checks if user exists"""
    user, code = sqlEnd.get_user_by_username(username)
    if (code != 200):
        return False
    if user:
        return True
    return False

def isOTP(username):
    """Checks if username entered needs an OTP"""
    user, code = sqlEnd.get_user_by_username(username)
    if code != 200:
        return False
    if user.totp_secret:
        return True
    return False

def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(weeks=4)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["username"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def register(username, password):
    """Register a user"""
    req, code = sqlEnd.add_user(username, password)
    if (code != 200):
        return {"error": req["error"]}, code
    else:
        return {"message": req["message"]}, code

def login(username, password):
    """Basic password check, pre login"""
    user, code = sqlEnd.get_user_by_username(username)
    if code != 200:
        return {"error": user["error"]}, code
    if not user:
        return {"error": "Username or password incorrect"}, 400
    if not bcrypt.verify(password, user.password_hash):
        return {"error": "Username or password incorrect"}, 400
    return {"message": "Login successful"}, 200


def login_w_otp(username, password, totp):
    """Login with OTP"""
    user, code = sqlEnd.get_user_by_username(username)
    if code != 200:
        return {"error": user["error"]}, code
    if not user:
        return {"error": "Username or password incorrect"}, 400
    if not bcrypt.verify(password, user.password_hash):
        return {"error": "Username or password incorrect"}, 400
    otp = pyotp.TOTP(user.totp_secret)
    if not otp.verify(totp, valid_window = 1):
        return {"error": "OTP invalid"}, 400
    return {"message": "Login successful"}, 200

def two_fa(username, password):
    if not isUser(username):
        return {"error": "User not found"}, 401
    if isOTP(username):
        return {"error": "2FA already enabled"}, 401
    req, code = login(username, password)
    if (code == 200):
        totp_secret = pyotp.random_base32()
        issuer = "passman"
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=issuer)
        return_req, code = sqlEnd.edit_user(username, password, totp_secret)
        if (code != 200):
            return {"error": return_req["error"]}, code
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return {"message": "Successful", "image": img_base64}, code
    else:
        return {"error": req["error"]}, code

def find_entries(username, jwt):
    """Return entries under username in Vault"""
    if decode_token(jwt) != username:
        return {"error": "Authentication error"}, 400
    sqlEnd.get_vault_entries_for_user(username)
    return {"message": "Successful"}, 200