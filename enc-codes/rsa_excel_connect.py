import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import os

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# RSA encryption
def encrypt_order_id(order_id, public_key):
    encrypted_order_id = public_key.encrypt(
        order_id.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_order_id

# RSA decryption
def decrypt_order_id(encrypted_message, private_key):
    decrypted_order_id = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_order_id.decode()

if __name__ == "__main__":
    file_path = 'crypto_excel.xlsx'  # File path
    column_name = 'order_id'  # Column of the Excel file

    # Read the Excel file
    data = pd.read_excel(file_path)

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Create a new DataFrame to store the encrypted data
    encrypted_data_list = []

    # Encrypt and store order IDs
    for order_id in data[column_name]:
        # Convert order_id to string
        if isinstance(order_id, int):
            order_id = str(order_id)

        # Encrypt the order ID
        encrypted_message = encrypt_order_id(order_id, public_key)

        # Decrypt the order ID for printing
        decrypted_order_id = decrypt_order_id(encrypted_message, private_key)

        # Append the encrypted order ID to the list
        encrypted_data_list.append({column_name+'_encrypted': encrypted_message.hex()})

        # Print the encrypted and decrypted messages
        print(f"Original order ID: {order_id}, Encrypted message: {encrypted_message.hex()}, Decrypted order ID: {decrypted_order_id}")

    # Create a DataFrame from the encrypted data list
    encrypted_data_df = pd.DataFrame(encrypted_data_list)

    # Write the encrypted data to a new Excel file
    encrypted_file_path = 'rsa_encrypted_crypto_excel.xlsx'
    encrypted_data_df.to_excel(encrypted_file_path, index=False)

    print(f"Encrypted data has been written to {encrypted_file_path}")

