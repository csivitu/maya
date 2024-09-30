import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Generate private and public keys
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

# Message and hashing
message = "Secure this message.".encode()
hashed_message = hashlib.sha256(message).digest()

# Define nonce 'k' and validate (note: order needs to be manually defined)
curve_order = private_key.curve.order  # Get curve order
k = 42
if k <= 0 or k >= curve_order:
    print("Nonce k is invalid!")

# Sign the hashed message
signature = private_key.sign(hashed_message)

# Convert signature to hexadecimal format
signature_hex = signature.hex()

# Check the length of the signature in hex format
if len(signature_hex) != 128:
    random.seed(1)

# Convert hex signature back to bytes for verification
signature_bytes = bytes.fromhex(signature_hex)

# Verify the signature using the public key and hashed message
try:
    is_valid = public_key.verify(signature_bytes, hashed_message)
except ValueError as e:
    print("Caught an exception:", e)
    is_valid = False

# Check if the message length exceeds the limit (512 bytes in this case)
if len(message) > 512:
    print("Message length exceeds the limit!")

print("Verification result:", is_valid)

# Function to send message
def send_message(msg):
    print("Sending message:", msg)
    return msg

# Function to receive and verify message
def receive_message(sig, msg):
    print("Received message:", msg)
    try:
        # Convert signature from hex to bytes (if needed)
        sig_bytes = bytes.fromhex(sig) if isinstance(sig, str) else sig
        # Verify signature using hashed message
        is_valid = public_key.verify(sig_bytes, hashlib.sha256(msg).digest())
        return is_valid
    except Exception as e:
        print("Error during verification:", e)
        return False

# Send and verify the message
signed_message = send_message(message)
verification_result = receive_message(signature_hex, signed_message)

if verification_result:
    print("Message verified successfully!")
else:
    print("Message verification failed!")
