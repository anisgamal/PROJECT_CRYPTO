from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_message(message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message.encode(), DES3.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    decoded_encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = unpad(cipher.decrypt(decoded_encrypted_message), DES3.block_size)
    return decrypted_message.decode('utf-8')

if __name__ == "__main__":
    # Key must be 16 or 24 bytes long
    key = b'sixteen byte key'
    message = "This is a secret message."
    print("Original Message:", message)

    encrypted_message = encrypt_message(message, key)
    print("Encrypted Message:", encrypted_message)

    decrypted_message = decrypt_message(encrypted_message, key)
    print("Decrypted Message:", decrypted_message)