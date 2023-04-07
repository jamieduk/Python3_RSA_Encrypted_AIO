#!/usr/bin/env python3
# (c)J~Net 2023
# jnet.sytes.net
#
# ./aio_4096.py
#
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

print("948 Chars Secure Messege Using 8192 Bit Key!")

def generate_key_pair():
    key_size=8192
    private_key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    public_key=private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"🔑 RSA {key_size} bit keypair generated and saved to 'private_key.pem' and 'public_key.pem'")


def encrypt_message():
    with open("public_key.pem", "rb") as key_file:
        public_key=serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    with open("message.txt", "rb") as message_file:
        message=message_file.read()
    ciphertext=public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_message=base64.b64encode(ciphertext)
    with open("encrypted.txt", "wb") as f:
        f.write(encrypted_message)
    print(f"🔏 Encrypted message saved to 'encrypted.txt'")


def decrypt_message():
    with open("private_key.pem", "rb") as key_file:
        private_key=serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    with open("encrypted.txt", "rb") as message_file:
        encrypted_message=message_file.read()
    ciphertext=base64.b64decode(encrypted_message)
    plaintext=private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open("decrypted.txt", "wb") as f:
        f.write(plaintext)
    print(f"🔓 Decrypted Message Saved To 'decrypted.txt'")


def main():
    while True:
        print("\nSelect an option:")
        print("1. 🔑 Generate Keypair")
        print("2. 🔏 Encrypt message")
        print("3. 🔓 Decrypt message")
        print("4. Exit")
        option=input("> ")
        if option == "1":
            generate_key_pair()
        elif option == "2":
            encrypt_message()
        elif option == "3":
            decrypt_message()
        elif option == "4":
            break
        else:
            print("Invalid option")


if __name__ == "__main__":
    main()

