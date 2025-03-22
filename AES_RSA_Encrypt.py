from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64


# RSA Key Pair Generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# Encrypt AES Key using RSA
def encrypt_aes_key(aes_key, recipient_public_key):
    rsa_key = RSA.import_key(recipient_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key


# AES Encryption in CTR Mode
def aes_encrypt_ctr(plaintext, aes_key):

    # Create a new AES cipher in CTR mode
    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext.encode())

    # Prepend nonce to the ciphertext
    encrypted_data = cipher.nonce + ciphertext

    return base64.b64encode(encrypted_data).decode()


if __name__ == "__main__":
    # Generate RSA Keys
    private_key, public_key = generate_rsa_keys()
    print("----- RSA Key Pair -----")
    print("Public Key:\n", public_key.decode())
    print("Private Key:\n", private_key.decode())

    # Generate AES Key 
    aes_key = get_random_bytes(32)  # 256-bit key
    print("\n----- AES Key (Base64) -----")
    print(base64.b64encode(aes_key).decode())

    # Securely Exchange AES Key using RSA
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    print("\n----- Encrypted AES Key (Base64) -----")
    print(base64.b64encode(encrypted_aes_key).decode())

    # Prompt user for plaintext and encrypt it using AES in CTR mode
    plaintext = input("\nEnter the plaintext you want to encrypt: ")
    encrypted_text = aes_encrypt_ctr(plaintext, aes_key)
    print("\n----- AES-CTR Encryption -----")
    print("Plaintext:", plaintext)
    print("Ciphertext (Base64):", encrypted_text)
