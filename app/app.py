from flask import Flask, request, jsonify
import sqlInterface as sql

app = Flask(__name__)

# API: Register
@app.route('/api/register', methods=['POST'])
def register():
    """API endpoint for registering, does not include adding 2-FA"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    check_pass = data.get('check_password')

    if password != check_pass:
        return jsonify({"error": "The passwords do not match"})

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
        return jsonify({"error": "Username and password required"}), 400

    if sql.login_w_otp(username, password, otp):
        return jsonify({"message": "Login successful", "token": sql.generate_token(username)}), 200
    else:
        return jsonify({"error": "Username or password incorrect"}), 400

@app.route('/api/vault', methods=['POST'])
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
    return jsonify({"message": "Login successful"}), 200

if __name__ == '__main__':
    app.run(debug=True)