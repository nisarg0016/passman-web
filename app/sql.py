from sqlLogin import *
import pyotp
import qrcode
import io
import base64

def isOTP(username):
    """Checks if username entered needs an OTP"""
    user = get_user_by_username(username)
    if user.totp_secret:
        return True
    return False

def login(username, password):
    """Basic password check, pre login"""
    user = get_user_by_username(username)
    if not user:
        print("User not found")
        return 0
    if not bcrypt.verify(password, user.password_hash):
        print("Invalid password")
        return 1
    return 2


def login_w_otp(username, password, totp):
    """Login with OTP and no OTP"""
    user = get_user_by_username(username)
    if not user:
        print("User not found")
        return False
    if not bcrypt.verify(password, user.password_hash):
        print("Invalid password")
        return False
    if user.totp_secret:
        otp = pyotp.TOTP(user.totp_secret)
        if not otp.verify(totp, valid_window = 1):
            print("OTP error")
            return False
    return True

def two_fa(username, password):
    if (login(username, password)):
        totp_secret = pyotp.random_base32()
        issuer = "MyPasswordManager"
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=issuer)
        return_req, code = edit_user(username, password, totp_secret)
        if (code != 200):
            return {"error": return_req["error"]}, code
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return {"message": "Successful", "image": img_base64}, code
    else:
        return {"message": "Login failure"}, 400