from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import pickle
import sys

# RSA Key Generation for Digital Signing and Encryption
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Client Side: Encrypt sensitive data, sign request, and send it to the server
def client_request(role, patient_data, private_key_client, public_key_server):
    # Encrypt sensitive details if role is "Doctor"
    if role == "Doctor":
        cipher_rsa = PKCS1_OAEP.new(public_key_server)
        patient_data['treatment'] = cipher_rsa.encrypt(patient_data['treatment'].encode())
        patient_data['expenses'] = cipher_rsa.encrypt(patient_data['expenses'].encode())
    elif role == "Nurse":
        # Nurses do not access sensitive details
        patient_data.pop('treatment', None)
        patient_data.pop('expenses', None)

    # Sign the request
    request_data = f"{role}:{patient_data}".encode()
    hash_request = SHA256.new(request_data)
    signature = pkcs1_15.new(private_key_client).sign(hash_request)

    # Package data to send to the server
    data_package = {
        'role': role,
        'patient_data': patient_data,
        'signature': signature
    }

    # Serialize data package (simulate sending to server by saving to file)
    with open("request_data.pkl", "wb") as file:
        pickle.dump(data_package, file)
    print(f"Data package for {role} sent to server (saved to file).")

# Server Side: Verify signature, check role, and respond with appropriate data
def server_process_request(data_package_path, public_key_client, private_key_server):
    # Load data package
    with open(data_package_path, "rb") as file:
        data_package = pickle.load(file)

    role = data_package['role']
    patient_data = data_package['patient_data']
    signature = data_package['signature']

    # Verify the digital signature
    request_data = f"{role}:{patient_data}".encode()
    hash_request = SHA256.new(request_data)
    try:
        pkcs1_15.new(public_key_client).verify(hash_request, signature)
        print("Signature verification succeeded.")
    except (ValueError, TypeError):
        print("Signature verification failed.")
        sys.exit()

    # Decrypt sensitive fields if requester is a doctor
    if role == "Doctor":
        cipher_rsa = PKCS1_OAEP.new(private_key_server)
        patient_data['treatment'] = cipher_rsa.decrypt(patient_data['treatment']).decode()
        patient_data['expenses'] = cipher_rsa.decrypt(patient_data['expenses']).decode()
        print("Full Patient Details (Doctor Access):", patient_data)
    elif role == "Nurse":
        print("Limited Patient Details (Nurse Access):", patient_data)
    else:
        print("Invalid role.")

# Main Program
if __name__ == "__main__":
    # Generate RSA Key Pairs for Client and Server
    private_key_client, public_key_client = generate_rsa_key_pair()
    private_key_server, public_key_server = generate_rsa_key_pair()

    # User input for role
    role = input("Enter role (Doctor/Nurse): ")
    if role not in ["Doctor", "Nurse"]:
        print("Invalid role. Please enter 'Doctor' or 'Nurse'.")
        sys.exit()

    # User input for patient data
    patient_data = {
        'name': input("Enter patient's name: "),
        'age': input("Enter patient's age: ")
    }
    if role == "Doctor":
        patient_data['treatment'] = input("Enter patient's treatment: ")
        patient_data['expenses'] = input("Enter patient's expenses: ")

    # Client encrypts and sends data
    client_request(role, patient_data, private_key_client, public_key_server)

    # Server receives and processes the request
    server_process_request("request_data.pkl", public_key_client, private_key_server)
