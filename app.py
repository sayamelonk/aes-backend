from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import hashlib
from flask_cors import CORS  # Import CORS module

app = Flask(__name__)

CORS(app)  # Menambahkan CORS

# Function for AES encryption
def encrypt_message(message, key):
    # Ensure key is 32 bytes long by padding or truncating
    key = hashlib.sha256(key.encode()).digest()[:32]
    
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')
  
# Function for AES decryption
def decrypt_message(encrypted_message, key):
    # Ensure key is 32 bytes long by padding or truncating
    key = hashlib.sha256(key.encode()).digest()[:32]
    
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

@app.route('/')
def home():
    return 'Hello from Flask on Vercel!'

# API for encryption
@app.route('/api/encrypt', methods=['POST'])  # Accepting only POST method
def encrypt():
    data = request.json
    message = data['message']
    key = data['key']
    encrypted_message = encrypt_message(message, key)
    return jsonify({'encrypted_message': encrypted_message})

# API for decryption
@app.route('/api/decrypt', methods=['POST'])  # Accepting only POST method
def decrypt():
    data = request.json
    encrypted_message = data['encrypted_message']
    key = data['key']
    decrypted_message = decrypt_message(encrypted_message, key)
    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True)
