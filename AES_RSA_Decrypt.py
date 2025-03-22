import sys
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

def decrypt_aes_key(encrypted_key_b64, private_key_pem):

    # Convert Base64 to raw bytes
    encrypted_key = base64.b64decode(encrypted_key_b64)

    # Import the RSA private key
    rsa_key = RSA.import_key(private_key_pem)

    # Decryption with PKCS1_OAEP padding
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

def aes_decrypt_ctr(ciphertext_b64, aes_key):

    raw_data = base64.b64decode(ciphertext_b64)

    # Default nonce size = 8 bytes
    nonce_size = AES.block_size // 2  
    nonce = raw_data[:nonce_size]
    ciphertext = raw_data[nonce_size:]

    # Create the AES-CTR cipher with the same nonce
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    plaintext_bytes = cipher.decrypt(ciphertext)

    # Interpret the plaintext
    return plaintext_bytes.decode('utf-8', errors='replace')

def introduce_bit_error(ciphertext_b64):
    
    raw_data = bytearray(base64.b64decode(ciphertext_b64))
    # Flip a bit in the middle
    middle_index = len(raw_data) // 2
    raw_data[middle_index] ^= 0x01
    return base64.b64encode(raw_data).decode()

def main():
    print("----- AES-CTR Decryption -----\n")

    # Read the RSA PRIVATE KEY from user input
    print("Paste your RSA PRIVATE KEY (including the BEGIN/END lines).")
    private_key_lines = []
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            break
        if not line or not line.strip():
            break
        private_key_lines.append(line)
    private_key_pem = "".join(private_key_lines).strip()
    print("\nPrivate key captured\n")

    #  Read Encrypted AES Key (Base64)
    encrypted_key_b64 = input("Enter the encrypted AES key (Base64): ").strip()

    #  Read Ciphertext (Base64)
    ciphertext_b64 = input("Enter the ciphertext (Base64): ").strip()

    #  Decrypt the AES key using RSA 
    try:
        aes_key = decrypt_aes_key(encrypted_key_b64, private_key_pem)
    except Exception as e:
        print("Error decrypting AES key with the provided RSA private key.")
        print("Exception:", e)
        sys.exit(1)

    #  Decrypt the ciphertext using AES-CTR 
    try:
        decrypted_text = aes_decrypt_ctr(ciphertext_b64, aes_key)
        print("\n----- DECRYPTION RESULT -----")
        print("Recovered Plaintext:", decrypted_text)
    except Exception as e:
        print("Error decrypting the ciphertext with the AES key.")
        print("Exception:", e)
        sys.exit(1)

    #  Effect of bit error in CTR mode 
    print("\n----- BIT ERROR DEMONSTRATION -----")
    corrupted_ciphertext_b64 = introduce_bit_error(ciphertext_b64)
    print("Corrupted Ciphertext (Base64):", corrupted_ciphertext_b64)

    try:
        corrupted_decryption = aes_decrypt_ctr(corrupted_ciphertext_b64, aes_key)
        print("Decrypted Text from corrupted ciphertext: ", corrupted_decryption)
    except Exception as e:
        print("Error decrypting the corrupted ciphertext.")
        print("Exception:", e)

if __name__ == "__main__":
    main()
