from gorgona_sender import GorgonaSender

# Generate keys
priv_pem, pub_pem, key_hash = GorgonaSender.generate_key_pair()

print(f"Your Public Key Hash: {key_hash}")
print("--- PRIVATE KEY (Save this safely!) ---")
print(priv_pem)
