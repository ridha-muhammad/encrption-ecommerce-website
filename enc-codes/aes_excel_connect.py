import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Encryption
def encrypt_order_id(order_id, secret_key):
    iv = os.urandom(16)  # Random initialization vector

    # Padding the order ID to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_order_id = padder.update(order_id.encode()) + padder.finalize()

    # Create AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())

    # Encrypt the padded order_id
    encryptor = cipher.encryptor()
    encrypted_order_id = encryptor.update(padded_order_id) + encryptor.finalize()

    # Return the encrypted order id and the initialization vector
    return iv + encrypted_order_id

# Decryption
def decrypt_order_id(encrypted_message, secret_key):
    iv = encrypted_message[:16]  # Extract the initialization vector
    encrypted_order_id = encrypted_message[16:]  # Extract the encrypted order ID

    # AES cipher with CBC mode using the same secret key and initialization vector
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())

    # Decrypt order ID
    decryptor = cipher.decryptor()
    decrypted_padded_order_id = decryptor.update(encrypted_order_id) + decryptor.finalize()

    # Unpad the decrypted order ID
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_order_id = unpadder.update(decrypted_padded_order_id) + unpadder.finalize()

    # Convert decrypted order ID from bytes to string
    return decrypted_order_id.decode()

if __name__ == "__main__":
    # Read the Excel or CSV file
    file_path = 'crypto_excel.xlsx' # File path
    column_name = 'order_id'  # Column to be encrypted
    data = pd.read_excel(file_path) 

    # Generate a secret key
    secret_key = os.urandom(16) 

    # List to store encrypted data
    encrypted_data_list = []

    # Loop through each value in the specified column
    for order_id in data[column_name]:
        # Convert order_id to string if it's an integer
        if isinstance(order_id, int):
            order_id = str(order_id)

        # Encrypt the order ID
        encrypted_message = encrypt_order_id(order_id, secret_key)

        # Append the encrypted order ID to the list
        encrypted_data_list.append(encrypted_message.hex())

        # Decrypt the order ID (just for demonstration purposes)
        decrypted_order_id = decrypt_order_id(encrypted_message, secret_key)
        print(f"Original order ID: {order_id}, Encrypted message: {encrypted_message.hex()}, Decrypted order ID: {decrypted_order_id}")

    # Create a DataFrame from the encrypted data list
    encrypted_data_df = pd.DataFrame({column_name+'_encrypted': encrypted_data_list})

    # Write the encrypted data to a new Excel file
    encrypted_file_path = 'aes_encrypted_crypto_excel.xlsx' # New file path
    encrypted_data_df.to_excel(encrypted_file_path, index=False)

    print(f"Encrypted data has been written to {encrypted_file_path}")