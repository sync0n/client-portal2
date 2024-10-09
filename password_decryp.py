import subprocess
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def run_curl_command():
    """
    Runs the curl command to fetch user data from the backend.
    """
    curl_command = [
        'curl', '-X', 'GET',
        'http://3.79.179.54:8080/api/v1/accounts?email=mariika.kulmala@gmail.com'
    ]
    
    try:
        # Run the curl command and capture the output
        result = subprocess.run(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        # Check if there was an error in curl execution
        if result.returncode != 0:
            print(f"Error in curl command: {result.stderr.decode('utf-8')}")
            return None
        # Return the output decoded as a string
        return result.stdout.decode('utf-8')
    except subprocess.TimeoutExpired:
        print("The curl command timed out.")
        return None

def decrypt_password(encrypted_password, secret_key):
    """
    Decrypts the given encrypted password using AES/ECB/PKCS5Padding.
    """
    # Ensure the secret key is 24 bytes
    if len(secret_key) != 24:
        raise ValueError("Secret key must be exactly 24 characters long for AES-192.")
    
    # Convert the secret key to bytes
    key_bytes = secret_key.encode('utf-8')
    
    # Decode the Base64-encoded encrypted password
    encrypted_bytes = base64.b64decode(encrypted_password)
    
    # Initialize the AES cipher (AES/ECB/PKCS5Padding)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    
    # Decrypt and unpad the result
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    decrypted_password = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
    
    return decrypted_password

def main():
    # Run the curl command and fetch the data
    raw_data = run_curl_command()

    # Check if data was retrieved successfully
    if raw_data is None:
        print("Failed to retrieve data from the server.")
        return

    # Print raw data for debugging
    print("Raw Data:", raw_data)

    # Check if the response is empty
    if not raw_data.strip():
        print("Received empty response from the server.")
        return

    # Parse the JSON response
    try:
        users = json.loads(raw_data)
        print(f"Parsed JSON: {users}")  # Print parsed JSON for inspection

        # Ensure it's a list
        if not isinstance(users, list):
            print("Expected a list of users, but received something else.")
            return
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON. Error: {e}")
        return

    # Ask the user for the decryption key
    secret_key = input("Enter the decryption key (must be 24 characters long): ")

    # Process each user
    for user in users:
        try:
            email = user['email']
            encrypted_password = user['password']

            # Decrypt the password
            decrypted_password = decrypt_password(encrypted_password, secret_key)
            print(f"Email: {email}")
            print(f"Decrypted Password: {decrypted_password}")
        except KeyError:
            print("Invalid data structure for user, missing 'email' or 'password'.")
        except Exception as e:
            print(f"Failed to decrypt password for {email}. Error: {e}")

if __name__ == "__main__":
    main()
