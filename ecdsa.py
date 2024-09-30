import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1

private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifyingKey

message = "Secure this message.".encode()
hashed_message = hashlib.sha256(message).digest()

k = 42

if k <= 0 or k >= SECP256k1.order:
    print("Nonce k is invalid!")

signature = private_key.sign(hashed_message)

signature_hex = signature.hex()

if len(signature_hex) != 128:
    random.seed(1)

is_valid = public_key.verify(signature, hashed_message)

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
    return public_key.verify(sig, hashed_message)

signed_message = send_message(message)
verification_result = receive_message(signature_hex, signed_message)

if verification_result:
    print("Message verified successfully!")
else:
    print("Message verification failed!")
