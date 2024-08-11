# import pandas as pd
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives import padding as sym_padding
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import os
# import time

# # Generate RSA keys
# def generate_rsa_keys():
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#         backend=default_backend()
#     )
#     public_key = private_key.public_key()
#     return private_key, public_key

# # RSA encryption
# def rsa_encrypt(order_id, public_key):
#     # Convert order_id to string
#     order_id_str = str(order_id)
    
#     # Encrypt the order ID
#     encrypted_order_id = public_key.encrypt(
#         order_id_str.encode(),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return encrypted_order_id

# # RSA decryption
# def rsa_decrypt(encrypted_message, private_key):
#     # Decrypt the order ID
#     decrypted_order_id = private_key.decrypt(
#         encrypted_message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return decrypted_order_id.decode()

# # AES encryption
# def aes_encrypt(order_id, secret_key):
#     iv = os.urandom(16)  # Random initialization vector

#     # Padding the order ID to be a multiple of 16 bytes (AES block size)
#     padder = sym_padding.PKCS7(128).padder()
#     padded_order_id = padder.update(order_id.encode()) + padder.finalize()

#     # Create AES cipher with CBC mode
#     cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())

#     # Encrypt the padded order_id
#     encryptor = cipher.encryptor()
#     encrypted_order_id = encryptor.update(padded_order_id) + encryptor.finalize()

#     # Return the encrypted order id and the initialization vector
#     return iv + encrypted_order_id

# # AES decryption
# def aes_decrypt(encrypted_message, secret_key, iv):
#     # AES cipher with CBC mode using the same secret key and initialization vector
#     cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())

#     # Decrypt order ID
#     decryptor = cipher.decryptor()
#     decrypted_padded_order_id = decryptor.update(encrypted_message) + decryptor.finalize()

#     # Unpad the decrypted order ID
#     unpadder = sym_padding.PKCS7(128).unpadder()
#     decrypted_order_id = unpadder.update(decrypted_padded_order_id) + unpadder.finalize()

#     # Convert decrypted order ID from bytes to string
#     return decrypted_order_id.decode()

# if __name__ == "__main__":
#     file_path = 'crypto_excel.xlsx'  # File path
#     column_name = 'order_id'  # Column of the Excel file

#     # Read the Excel file
#     data = pd.read_excel(file_path)

#     # Generate RSA keys
#     private_key, public_key = generate_rsa_keys()

#     # Create a new DataFrame to store the encrypted data
#     encrypted_data_list_rsa = []

#     # Encrypt and store order IDs using RSA
#     start_time = time.time()
#     for order_id in data[column_name]:
#         # Encrypt the order ID
#         encrypted_message = rsa_encrypt(order_id, public_key)
        
#         # Append the encrypted order ID to the list
#         encrypted_data_list_rsa.append({column_name+'_encrypted': encrypted_message.hex()})

#         # Decrypt the order ID for printing
#         decrypted_order_id = rsa_decrypt(encrypted_message, private_key)

#         # Print the encrypted and decrypted messages
#         print(f"Original order ID: {order_id}, Encrypted message (RSA): {encrypted_message.hex()}, Decrypted order ID (RSA): {decrypted_order_id}")

#     # Calculate and print RSA encryption time
#     rsa_encryption_time = time.time() - start_time
#     print(f"\nAverage RSA Encryption Time: {rsa_encryption_time / len(data[column_name])} seconds")

#     # Write the encrypted data to a new Excel file
#     encrypted_file_path_rsa = 'rsa_encrypted_crypto_excel.xlsx'
#     pd.DataFrame(encrypted_data_list_rsa).to_excel(encrypted_file_path_rsa, index=False)
#     print(f"Encrypted data using RSA has been written to {encrypted_file_path_rsa}")

#     # Generate AES key
#     aes_key = os.urandom(32)

#     # Create a new DataFrame to store the encrypted data using AES
#     encrypted_data_list_aes = []

#     # Encrypt and store order IDs using AES
#     start_time = time.time()
#     for order_id in data[column_name]:
#         # Encrypt the order ID
#         encrypted_message = aes_encrypt(str(order_id), aes_key)
        
#         # Append the encrypted order ID to the list
#         encrypted_data_list_aes.append({column_name+'_encrypted': encrypted_message.hex()})

#         # Print the encrypted message
#         print(f"Original order ID: {order_id}, Encrypted message (AES): {encrypted_message.hex()}")

#     # Calculate and print AES encryption time
#     aes_encryption_time = time.time() - start_time
#     print(f"\nAverage AES Encryption Time: {aes_encryption_time / len(data[column_name])} seconds")

#     # Write the encrypted data to a new Excel file
#     encrypted_file_path_aes = 'aes_encrypted_crypto_excel.xlsx'
#     pd.DataFrame(encrypted_data_list_aes).to_excel(encrypted_file_path_aes, index=False)
#     print(f"Encrypted data using AES has been written to {encrypted_file_path_aes}")




import pandas as pd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import os
import time

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
def encrypt_rsa(order_id, public_key):
    # Measure encryption time
    start_time = time.time()
    encrypted_order_id = public_key.encrypt(
        order_id.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encryption_time = time.time() - start_time
    return encrypted_order_id, encryption_time

# RSA decryption
def decrypt_rsa(encrypted_message, private_key):
    decrypted_order_id = private_key.decrypt(
        encrypted_message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_order_id.decode()

# AES encryption
def encrypt_aes(order_id, secret_key):
    iv = os.urandom(16)  # Random initialization vector

    # Padding the order ID to be a multiple of 16 bytes (AES block size)
    padder = padding.PKCS7(128).padder()
    padded_order_id = padder.update(order_id.encode()) + padder.finalize()

    # Create AES cipher with CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())

    # Encrypt the padded order_id
    encryptor = cipher.encryptor()

    # Measure encryption time
    start_time = time.time()
    encrypted_order_id = encryptor.update(padded_order_id) + encryptor.finalize()
    encryption_time = time.time() - start_time

    # Return the encrypted order id, initialization vector, and encryption time
    return iv + encrypted_order_id, encryption_time

# AES decryption
def decrypt_aes(encrypted_message, secret_key):
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

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Generate AES secret key
    aes_secret_key = os.urandom(16) 

    # List to store encryption times
    rsa_encryption_times = []
    aes_encryption_times = []

    # Loop through each value in the specified column
    for order_id in data[column_name]:
        # Convert order_id to string if it's an integer
        if isinstance(order_id, int):
            order_id = str(order_id)

        # Encrypt using RSA
        encrypted_message, encryption_time = encrypt_rsa(order_id, public_key)
        rsa_encryption_times.append(encryption_time)

        # Decrypt the order ID (just for demonstration purposes)
        decrypted_order_id = decrypt_rsa(encrypted_message, private_key)
        print(f"Original order ID: {order_id}, RSA Encrypted message: {encrypted_message.hex()}, Decrypted order ID: {decrypted_order_id}")

        # Encrypt using AES
        encrypted_message, encryption_time = encrypt_aes(order_id, aes_secret_key)
        aes_encryption_times.append(encryption_time)

        # Decrypt the order ID (just for demonstration purposes)
        decrypted_order_id = decrypt_aes(encrypted_message, aes_secret_key)
        print(f"Original order ID: {order_id}, AES Encrypted message: {encrypted_message.hex()}, Decrypted order ID: {decrypted_order_id}")

    # Calculate and print the average encryption times
    average_rsa_encryption_time = sum(rsa_encryption_times) / len(rsa_encryption_times)
    average_aes_encryption_time = sum(aes_encryption_times) / len(aes_encryption_times)
    print(f"Average RSA encryption time: {average_rsa_encryption_time} seconds")
    print(f"Average AES encryption time: {average_aes_encryption_time} seconds")
