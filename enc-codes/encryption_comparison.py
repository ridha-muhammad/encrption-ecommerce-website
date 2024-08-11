import time
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from rsa_excel_connect import generate_rsa_keys, encrypt_order_id, decrypt_order_id
from aes_excel_connect import encrypt_order_id, decrypt_order_id

# Define functions to measure execution time
def measure_execution_time(func, *args):
    start_time = time.time()
    func(*args)
    end_time = time.time()
    return end_time - start_time

# Define a function to measure memory usage
def measure_memory_usage(func, *args):
    # Implement memory measurement logic (not available in standard Python)
    pass

# Define a function to measure file size
def measure_file_size(file_path):
    return os.path.getsize(file_path)

if __name__ == "__main__":
    file_path = 'crypto_excel.xlsx'  # File path
    column_name = 'order_id'  # Column of the Excel file

    # Read the Excel file
    data = pd.read_excel(file_path)

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Measure execution time for RSA encryption
    rsa_execution_times = []
    for order_id in data[column_name]:
        execution_time = measure_execution_time(encrypt_order_id, order_id, public_key)
        rsa_execution_times.append(execution_time)

    # Measure execution time for AES encryption
    aes_execution_times = []
    for order_id in data[column_name]:
        execution_time = measure_execution_time(encrypt_order_id, order_id, secret_key)
        aes_execution_times.append(execution_time)

    # Measure memory usage for RSA and AES encryption
    rsa_memory_usage = measure_memory_usage(encrypt_order_id, data[column_name].iloc[0], public_key)
    aes_memory_usage = measure_memory_usage(encrypt_order_id, data[column_name].iloc[0], secret_key)

    # Measure file sizes for RSA and AES encrypted data
    rsa_encrypted_file_size = measure_file_size('rsa_encrypted_crypto_excel.xlsx')
    aes_encrypted_file_size = measure_file_size('aes_encrypted_crypto_excel.xlsx')

    # Create a table to summarize the results
    results = pd.DataFrame({
        'Metric': ['Execution Time (RSA)', 'Execution Time (AES)', 'Memory Usage (RSA)', 'Memory Usage (AES)', 'File Size (RSA)', 'File Size (AES)'],
        'Value': [sum(rsa_execution_times), sum(aes_execution_times), rsa_memory_usage, aes_memory_usage, rsa_encrypted_file_size, aes_encrypted_file_size]
    })

    print("Comparison Results:")
    print(results)

    # Generate graphs to visualize the results
    plt.bar(['RSA', 'AES'], [sum(rsa_execution_times), sum(aes_execution_times)], color=['blue', 'green'])
    plt.xlabel('Encryption Method')
    plt.ylabel('Total Execution Time')
    plt.title('Total Execution Time for RSA vs AES Encryption')
    plt.show()

    plt.bar(['RSA', 'AES'], [rsa_memory_usage, aes_memory_usage], color=['blue', 'green'])
    plt.xlabel('Encryption Method')
    plt.ylabel('Memory Usage')
    plt.title('Memory Usage for RSA vs AES Encryption')
    plt.show()

    plt.bar(['RSA', 'AES'], [rsa_encrypted_file_size, aes_encrypted_file_size], color=['blue', 'green'])
    plt.xlabel('Encryption Method')
    plt.ylabel('File Size')
    plt.title('File Size for RSA vs AES Encrypted Data')
    plt.show()
