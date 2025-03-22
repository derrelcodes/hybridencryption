AES_RSA_Encrypt.py
 Execute the script: python AES_RSA_Encrypt.py
 The program will automatically:
o Generate RSA key pair
o Generate AES key
o Encrypt AES key with RSA
 Enter the plaintext when prompted
IMPORTANT: After encryption, copy and save the following details to a text file as they
will be required for decryption:
 The entire RSA Private Key (including BEGIN/END lines)
 The Encrypted AES Key (Base64)
 The Ciphertext (Base64)


AES_RSA_Decrypt.py
 Execute the script: python AES_RSA_Decrypt.py
 When prompted:
o Paste the saved RSA private key (including BEGIN/END lines)
o Enter the saved encrypted AES key (Base64)
o Enter the saved ciphertext (Base64)
