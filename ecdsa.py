import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1

private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

message = "Secure this message.".encode()
hashed_message = hashlib.sha256(message).digest()

k = random.randint(1, SECP256k1.order - 1)  # <-- Changed k to be randomly generated

if k <= 0 or k >= SECP256k1.order:
    print("Nonce k is invalid!")

signature = private_key.sign(hashed_message)

signature_hex = signature.hex()

# Removed the hex length check and random.seed because it was unnecessary.
# if len(signature_hex) != 128:  
#     random.seed(1)

is_valid = public_key.verify(signature, hashed_message)  # <-- Changed to verify signature, not signature_hex

try:
    if not is_valid:
        raise ValueError("Signature verification failed!")
except ValueError as e:
    print("Caught an exception:", e)

if len(message) > 512:
    print("Message length exceeds the limit!")

print("Verification result:", is_valid)

def send_message(msg):
    print("Sending message:", msg)
    return msg

def receive_message(sig, msg):
    print("Received message:", msg)
    return public_key.verify(sig, hashed_message)  # <-- Changed to verify using signature, not signature_hex

signed_message = send_message(message)
verification_result = receive_message(signature, signed_message)  # <-- Changed to pass signature, not signature_hex

if verification_result:
    print("Message verified successfully!")
else:
    print("Message verification failed!")

# Length Checking of the Hash should be fixed to be specific to the hash algorithm.
if len(hashed_message) != 32:  # <-- Highlighted change for hash length checking (SHA-256 produces a 32-byte hash)
    print("Hash length is not correct!")  # <-- Added message for clarity

