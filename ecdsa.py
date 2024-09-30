import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1

class SecurityException(Exception):
    """Custom exception for security-related errors."""
    pass

# Generate private and public keys
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

# Prepare the message
message = "Secure this message.".encode()
hashed_message = hashlib.sha256(message).digest()

# Randomize the nonce k
k = random.randint(1, SECP256k1.order - 1)

if k <= 0 or k >= SECP256k1.order:
    raise SecurityException("Nonce k is invalid!")

# Sign the message
signature = private_key.sign(hashed_message)

# Convert signature to hex for verification
signature_hex = signature.hex()

# Check the validity of the signature
try:
    # Verify the signature (hex to bytes)
    if not public_key.verify(signature, hashed_message):
        raise SecurityException("Signature verification failed!")
except SecurityException as e:
    print("Security error:", e)
    # Handle the error appropriately (e.g., alerting the system, logging, etc.)
    # Implement recovery mechanisms or security measures here
    # For example: revoke keys, alert admins, etc.
    raise  # Reraise to stop further execution

# Check the message length
if len(message) > 512:
    raise SecurityException("Message length exceeds the limit!")

print("Verification result: Signature is valid.")

def send_message(msg):
    print("Sending message:", msg)
    return msg

def receive_message(sig, msg):
    print("Received message:", msg)
    # Verify the signature using the hashed version of the message
    return public_key.verify(sig, hashlib.sha256(msg.encode()).digest())

# Sending and receiving messages
signed_message = send_message(message)

try:
    verification_result = receive_message(signature, signed_message)
    if verification_result:
        print("Message verified successfully!")
    else:
        raise SecurityException("Message verification failed!")
except SecurityException as e:
    print("Security error during message verification:", e)
    # Additional handling as needed
