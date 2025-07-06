from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import sqlInterface as sql

app = Flask(__name__)
cors = CORS(app)

# API: Register
@app.route('/api/register', methods=['POST'])
def register():
    """API endpoint for registering, does not include adding 2-FA"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    check_pass = data.get('check_password')

    if password != check_pass:
        return jsonify({"error": "The passwords do not match"}), 400

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    return_req, code = sql.register(username, password)
    if (code == 401):
        return jsonify({"error": return_req["error"]}), code
    return jsonify({"message": return_req["message"]}), code
    
@app.route('/api/addtfa', methods=['POST'])
def add2fa():
    """API endpoint for login, OTP check is after"""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    return_req, code = sql.two_fa(username, password)
    if (code == 400):
        return jsonify({"error": return_req["error"]}), code
    else:
        return jsonify({"message": return_req["message"], "image": return_req["image"]}), code

# API: Login
@app.route('/api/login', methods=['POST'])
def login():
    """API endpoint for login, OTP check is after"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    auth = request.headers.get("Authorization")
    jwt = None
    if not auth or not auth.startswith("Bearer "):
        jwt = None
    else:
        jwt = auth.split(" ")[1]
    if not username or (not password and not jwt):
        return jsonify({"error": "Username and password required"}), 400

    if jwt and sql.decode_token(jwt) == username:
        return jsonify({"message": "Login successful"}), 200

    return_req, code = sql.login(username, password)
    if code == 200:
        if (sql.isOTP(username)):
            return jsonify({"message": return_req["message"], "two_fa": sql.isOTP(username)}), code
        else:
            return jsonify({"message": return_req["message"], "token": sql.generate_token(username)}), code
    else:
        return jsonify({"error": return_req["error"]}), code

@app.route('/api/loginotp', methods=['POST'])
def loginotp():
    """API endpoint for login, OTP check is after"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    otp = data.get('otp')

    if not username or not password:
        return jsonify({"error": "Username and password required."}), 400

    return_req, code = sql.login_w_otp(username, password, otp)
    if code == 200:
        return jsonify({"message": "Login successful.", "token": sql.generate_token(username)}), 200
    else:
        return jsonify({"error": return_req["error"]}), code

@app.route('/api/getvault', methods=['POST'])
def vaultFetch():
    """API endpoint for fetching vault entries"""
    data = request.json
    username = data.get('username')
    auth = request.headers.get("Authorization")
    jwt = None
    if not auth or not auth.startswith("Bearer "):
        jwt = None
    else:
        jwt = auth.split(" ")[1]
    if not username or not jwt:
        return jsonify({"error": "Authentication error"}), 400

    ret, code = sql.find_entries(username, jwt)
    if code != 200:
        return jsonify({"error": "Authentication error"}), 400
    return jsonify({"message": "Vault entries retrieved successfully", "entries": ret}), 200

@app.route('/api/addvault', methods=['POST'])
def vaultAdd():
    """API endpoint for adding vault entries"""
    data = request.json
    title = data.get('title')
    username = data.get('username')
    site = data.get('site')
    category = data.get('category')
    site_username = data.get('site_username')
    site_password = data.get('site_password')
    notes = data.get('notes')
    auth = request.headers.get("Authorization")
    jwt = None
    if not auth or not auth.startswith("Bearer "):
        jwt = None
    else:
        jwt = auth.split(" ")[1]
    if not username or not jwt:
        return jsonify({"error": "Authentication error"}), 400

    ret, code = sql.add_vault_entry(username, site, site_username, site_password, notes, jwt)
    if code != 200:
        return jsonify({"error": "Authentication error"}), 400
    return jsonify({"message": "Vault entry added successfully"}), 200

@app.route('/api/refreshjwt', methods=['POST'])
def refresh_jwt():
    """API endpoint for refreshing JWT token"""
    data = request.json
    username = data.get('username')
    auth = request.headers.get("Authorization")
    jwt = None
    if not auth or not auth.startswith("Bearer "):
        jwt = None
    else:
        jwt = auth.split(" ")[1]
    if not username or not jwt:
        return jsonify({"error": "Authentication error"}), 400

    new_jwt = sql.refresh_token(username, jwt)
    if new_jwt:
        return jsonify({"message": "Token refreshed successfully", "token": new_jwt}), 200
    else:
        return jsonify({"error": "Failed to refresh token"}), 400

@app.route('/api/hi', methods=['GET'])
def hi():
    return jsonify({"message": "HI"}), 200

if __name__ == '__main__':
    app.run(debug=True)