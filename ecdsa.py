import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Generate private and public keys
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

# Prepare the message
message = "Secure this message.".encode()

# Hash the message
hashed_message = hashlib.sha256(message).digest()

# Randomize the nonce k
k = random.randint(1, SECP256k1.order - 1)

if k <= 0 or k >= SECP256k1.order:
    raise ValueError("Nonce k is invalid!")

# Sign the message
signature = private_key.sign(hashed_message)

# Convert signature to hex for verification
signature_hex = signature.hex()

# Verify signature length (ensure it is 128 hex characters, which corresponds to 64 bytes)
if len(signature_hex) != 128:
    raise ValueError("Signature length is invalid!")

# Verify the signature
try:
    is_valid = public_key.verify(bytes.fromhex(signature_hex), hashed_message)
    if not is_valid:
        raise ValueError("Signature verification failed!")
except ValueError as e:
    print("Caught an exception:", e)
    is_valid = False

# Check the message length
if len(message) > 512:
    print("Message length exceeds the limit!")

print("Verification result:", is_valid)

def send_message(msg):
    print("Sending message:", msg)
    return msg

def receive_message(sig, msg):
    print("Received message:", msg)
    return public_key.verify(bytes.fromhex(sig), hashlib.sha256(msg.encode()).digest())

# Sending and receiving messages
signed_message = send_message(message)
verification_result = receive_message(signature_hex, signed_message)

if verification_result:
    print("Message verified successfully!")
else:
    print("Message verification failed!")
