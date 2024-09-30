import hashlib
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Generate private and public keys
private_key = SigningKey.generate(curve=SECP256k1)
public_key = private_key.verifying_key

# Message and hashing
message = "Secure this message.".encode()  # Ensure message is in bytes format
hashed_message = hashlib.sha256(message).digest()  # Hash the message using SHA-256

# Define nonce 'k' and validate (note: order needs to be manually defined)
curve_order = private_key.curve.order  # Get the curve order
k = 42  # Example fixed nonce value for testing
if k <= 0 or k >= curve_order:
    print("Nonce k is invalid!")  # Validate k is within correct bounds

# Sign the hashed message using the private key
signature = private_key.sign(hashed_message)

# Convert the signature to hexadecimal format for easier transmission/storage
signature_hex = signature.hex()

# Check the length of the signature in hex format (expected length is 128 characters)
if len(signature_hex) != 128:
    random.seed(1)  # Reset random seed if signature length is unexpected (debugging purpose)

# Convert hex signature back to bytes for verification (verify needs bytes)
signature_bytes = bytes.fromhex(signature_hex)

# Verify the signature using the public key and hashed message
try:
    is_valid = public_key.verify(signature_bytes, hashed_message)
except ValueError as e:
    print("Caught an exception during verification:", e)
    is_valid = False

# Check if the message length exceeds a predefined limit (512 bytes in this case)
if len(message) > 512:
    print("Message length exceeds the limit!")

print("Verification result:", is_valid)

# Function to send a message (simulating transmission)
def send_message(msg):
    if isinstance(msg, bytes):  # Ensure the message is in bytes format for consistency
        print("Sending message:", msg)
        return msg
    else:
        raise TypeError("Message should be in bytes format!")

# Function to receive and verify a message along with its signature
def receive_message(sig, msg):
    print("Received message:", msg)
    try:
        # Convert signature from hex to bytes if needed
        sig_bytes = bytes.fromhex(sig) if isinstance(sig, str) else sig
        
        # Verify signature using hashed message (rehash the received message)
        msg_hash = hashlib.sha256(msg).digest()
        is_valid = public_key.verify(sig_bytes, msg_hash)
        return is_valid
    except ValueError as e:
        print("Error during verification:", e)
        return False
    except Exception as e:
        print("Unexpected error:", e)
        return False

# Send and verify the message
signed_message = send_message(message)
verification_result = receive_message(signature_hex, signed_message)

# Print the result of verification
if verification_result:
    print("Message verified successfully!")
else:
    print("Message verification failed!")
