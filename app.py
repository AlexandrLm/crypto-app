from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)
CORS(app)

# Инициализируем пустые ключи, они будут генерироваться по запросу
rsa_private_key = None
rsa_public_key = None

@app.route('/api/generate-keys', methods=['GET'])
def generate_keys():
    global rsa_private_key, rsa_public_key
    try:
        print("Generating RSA keys...")
        rsa_key = RSA.generate(1024)
        rsa_private_key = rsa_key.export_key()
        rsa_public_key = rsa_key.publickey().export_key()
        print("Keys generated successfully")
        return jsonify({
            "rsa_public_key": rsa_public_key.decode('utf-8'),
            "rsa_private_key": rsa_private_key.decode('utf-8')
        })
    except Exception as e:
        print(f"Error generating keys: {str(e)}")
        return jsonify({"error": f"Failed to generate keys: {str(e)}"}), 500

# def compute_hash(digest):
#     if not digest:
#         raise ValueError("Digest not provided")
#     try:
#         h = int(digest.encode('utf-8').hex(), 16)
#         return str(h)
#     except ValueError as ve:
#         raise ValueError(f"Invalid digest format: {str(ve)}")
#     except Exception as e:
#         raise Exception(f"Hash computation failed: {str(e)}")

def compute_hash(digest):
    if not digest:
        raise ValueError("Digest not provided")
    try:
        H_prev = 100  # H0 (можно выбрать другое значение)
        n = 2**16 + 1  # Пример n (можно выбрать другое)
        for char in digest:
            M_i = ord(char)
            H_prev = (H_prev + M_i) ** 2 % n
        return str(H_prev)
    except Exception as e:
        raise Exception(f"Hash computation failed: {str(e)}")

def generate_signature(hash_value, rsa_private_key):
    if not hash_value or not rsa_private_key:
        raise ValueError("Hash or private key not provided")
    try:
        private_key = RSA.import_key(rsa_private_key)
        h = SHA256.new(hash_value.encode('utf-8'))
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(h)
        return {"signature": base64.b64encode(signature).decode('utf-8')}
    except Exception as e:
        raise Exception(f"Signing failed: {str(e)}")

def verify_signature(hash_value, signature, rsa_public_key):
    if not hash_value or not signature or not rsa_public_key:
        raise ValueError("Hash, signature or public key not provided")
    try:
        public_key = RSA.import_key(rsa_public_key)
        h = SHA256.new(hash_value.encode('utf-8'))
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(h, base64.b64decode(signature))
    except Exception as e:
        print(f"Verification error: {str(e)}")
        return False

@app.route('/api/hash', methods=['POST'])
def hash_text():
    global rsa_public_key
    data = request.get_json()
    digest = data.get('digest')
    try:
        result = {"hash": compute_hash(digest)}
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/sign', methods=['POST'])
def sign_text():
    global rsa_private_key
    data = request.get_json()
    hash_value = data.get('hash')
    try:
        result = generate_signature(hash_value, rsa_private_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    global rsa_public_key, rsa_private_key
    data = request.get_json()
    text = data.get('text')
    digest = data.get('digest')
    if not text or not rsa_public_key or not rsa_private_key:
        return jsonify({"error": "Keys not generated"}), 400

    message = text.encode('utf-8')
    length_bytes = len(message).to_bytes(2, 'big')
    message_with_length = length_bytes + message

    try:
        hash_value = compute_hash(digest)
        sign_result = generate_signature(hash_value, rsa_private_key)
        signature = sign_result['signature']

        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        gamma = b''
        for _ in range((len(message_with_length) + 15) // 16 + 1):
            gamma += session_key
        gamma = gamma[:len(message_with_length)]

        encrypted_message = base64.b64encode(bytearray(x ^ y for x, y in zip(message_with_length, gamma))).decode('utf-8')

        return jsonify({
            "encrypted_text": encrypted_message,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "signature": signature,
            "digest": digest
        })
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    global rsa_private_key, rsa_public_key
    data = request.get_json()
    encrypted_text = data.get('encrypted_text')
    encrypted_session_key = data.get('encrypted_session_key')
    signature = data.get('signature')
    digest = data.get('digest')
    if not encrypted_text or not rsa_private_key or not encrypted_session_key or not signature or not digest:
        return jsonify({"error": "Missing required parameters"}), 400

    decrypted_text = "Decryption failed due to data corruption"
    is_valid = False

    try:
        # Попытка расшифровки сессионного ключа
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
        session_key = cipher_rsa.decrypt(base64.b64decode(encrypted_session_key))

        # Обратное гаммирование
        encrypted_message = base64.b64decode(encrypted_text)
        gamma = b''
        for _ in range((len(encrypted_message) + 15) // 16 + 1):
            gamma += session_key
        gamma = gamma[:len(encrypted_message)]
        decrypted_message = bytearray(x ^ y for x, y in zip(encrypted_message, gamma))

        # Извлечение длины и текста
        length = int.from_bytes(decrypted_message[:2], 'big')
        print(f"Extracted length: {length}")
        decrypted_text = decrypted_message[2:2 + length].decode('utf-8')
        print(f"Decrypted text: {decrypted_text}")
    except Exception as e:
        print(f"Decryption error: {str(e)}")

    # Вычисление хеша для проверки
    try:
        original_hash = compute_hash(digest)
        # Проверка подписи только если расшифровка успешна
        if decrypted_text != "Decryption failed due to data corruption":
            is_valid = verify_signature(original_hash, signature, rsa_public_key)
        else:
            is_valid = False  # Подпись недействительна при сбое расшифровки
    except Exception as e:
        print(f"Verification error: {str(e)}")
        is_valid = False

    return jsonify({
        "decrypted": decrypted_text,
        "signature_valid": is_valid
    })

if __name__ == '__main__':
    app.run(host='192.168.1.146', debug=True, port=5000)