
from Crypto.Cipher import DES3, ARC4
from Crypto.Util.Padding import pad, unpad
import base64

# Triple DES (3DES) Encryption and Decryption
def triple_des_encrypt(message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message.encode(), DES3.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message).decode('utf-8')

def triple_des_decrypt(encrypted_message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    decoded_encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = unpad(cipher.decrypt(decoded_encrypted_message), DES3.block_size)
    return decrypted_message.decode('utf-8')

# Rabbit Encryption and Decryption (using ARC4 as a substitute)
def rabbit_encrypt(message, key):
    cipher = ARC4.new(key.encode())
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode('utf-8')

def rabbit_decrypt(encrypted_message, key):
    cipher = ARC4.new(key.encode())
    decoded_encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = cipher.decrypt(decoded_encrypted_message)
    return decrypted_message.decode('utf-8')

if __name__ == "__main__":
    # Triple DES (3DES) Example
    des_key = b'sixteen byte key'  # Key must be 16 or 24 bytes long
    des_message = "This is a secret message for 3DES."
    print("Original Message (3DES):", des_message)

    des_encrypted_message = triple_des_encrypt(des_message, des_key)
