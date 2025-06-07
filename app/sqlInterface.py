import sqlEnd
import pyotp
import qrcode
import io
import base64

def isUser(username):
    """Checks if user exists"""
    user, code = get_user_by_username(username)
    if (code != 200):
        return False
    return True

def isOTP(username):
    """Checks if username entered needs an OTP"""
    user, code = get_user_by_username(username)
    if user.totp_secret:
        return True
    return False

def register(username, password):
    """Register a user"""
    req, code = sqlEnd.add_user(username, password)
    if (code != 200):
        return {"error": req["error"]}, code
    else:
        return {"message": req["message"]}, code

def login(username, password):
    """Basic password check, pre login"""
    user = sqlEnd.get_user_by_username(username)
    if not user:
        return {"error": "Username or password incorrect"}, 400
    if not bcrypt.verify(password, user.password_hash):
        return {"error": "Username or password incorrect"}, 400
    return {"message": "Login successful"}, 200


def login_w_otp(username, password, totp):
    """Login with OTP and no OTP"""
    user, code = sqlEnd.get_user_by_username(username)
    if code != 200:
        return {"error": user["error"]}, code
    if not user:
        return {"error": "Username or password incorrect"}, 400
    if not bcrypt.verify(password, user.password_hash):
        return {"error": "Username or password incorrect"}, 400
    if user.totp_secret:
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