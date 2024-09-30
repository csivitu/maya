import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Generate private and public keys
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

# Message to be encrypted and signed
message = "Secure this message.".encode()

# AES encryption
def encrypt_message(message, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    # Create cipher configuration
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the message to be AES block size compliant
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()

    # Encrypt the padded message
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV for use in decryption

# AES decryption
def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]  # Extract the IV from the beginning
    actual_ciphertext = ciphertext[16:]  # Get the actual ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the decrypted message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

# Generate a random AES key (16 bytes for AES-128)
aes_key = os.urandom(16)

# Encrypt the message
encrypted_message = encrypt_message(message, aes_key)

# Hash the original message for signing
hashed_message = hashlib.sha256(message).digest()

# Sign the hashed message using the private key
signature = private_key.sign(hashed_message)

# Convert the signature to hexadecimal format
signature_hex = signature.hex()

# Verify the signature using the public key and hashed message
try:
    is_valid = public_key.verify(bytes.fromhex(signature_hex), hashed_message)
except ValueError as e:
    print("Caught an exception during verification:", e)
    is_valid = False

# Check if the message length exceeds a predefined limit (512 bytes in this case)
if len(message) > 512:
    print("Message length exceeds the limit!")

print("Verification result:", is_valid)

# Function to send a message (simulating transmission)
def send_message(msg):
    if isinstance(msg, bytes):  # Ensure the message is in bytes format
        print("Sending message:", msg)
        return msg
    else:
        raise TypeError("Message should be in bytes format!")

# Function to receive and verify message
def receive_message(sig, msg):
    print("Received message:", msg)
    try:
        # Verify signature using the hashed message
        is_valid = public_key.verify(bytes.fromhex(sig), hashlib.sha256(msg).digest())
        return is_valid
    except ValueError as e:
        print("Error during verification:", e)
        return False

# Send and verify the encrypted message
signed_message = send_message(encrypted_message)
verification_result = receive_message(signature_hex, signed_message)

# Decrypt the message after verification
if verification_result:
    decrypted_message = decrypt_message(signed_message, aes_key)
    print("Decrypted message:", decrypted_message.decode())
else:
    print("Message verification failed!")
