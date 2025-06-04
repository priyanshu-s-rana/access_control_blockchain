from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
from .dynamic_accumulator import RsaAccumulator
from dotenv import load_dotenv
import hashlib
import datetime
import ipfshttpclient
# import ipfsapi
import os
import json
from web3 import Web3, HTTPProvider
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
import pickle
import random
import pyaes, pbkdf2, binascii, secrets
import base64
import io
import matplotlib
matplotlib.use('Agg')
import time
import matplotlib.pyplot as plt
import mimetypes
import numpy as np
from .utils.SessionManager import session_manager

# Force reload of environment variables at startup
load_dotenv(override=True)

# api = ipfsapi.Client(host='http://127.0.0.1', port=5001)
global give_access

# Global settings
salt = os.getenv('SALT')
deployed_contract_address = os.getenv('DEPLOYED_CONTRACT_ADDRESS')
blockchain_address = os.getenv('BLOCKCHAIN_ADDRESS')
contract_file = os.getenv('CONTRACT_FILE')


def get_user_session(request) -> dict:
    """Helper function to get user information from session"""
    session_manager.cleanup_expired_sessions()  # Clean up expired sessions before checking
    session_id = request.COOKIES.get('session_id')
    if session_id:
        return session_manager.get_session(session_id)
    return None

def save_user_session(request, render_template: str, context: str, user_data: dict):
    """Helper function to save user information in session"""
    session_id = hashlib.sha256(f"{user_data['username']}{user_data['user_id']}".encode()).hexdigest()
        # Generate a new session ID if it doesn't exist
    session_manager.create_session(session_id, user_data)
    print("="*30)
    print(session_manager.get_session(session_id))
    print("="*30)
    response = render(request, render_template, context)
    response.set_cookie('session_id', session_id, max_age=3600*24)
    return response

def update_cookie(request, response, user_data: dict):
    """Update the session cookie with new user data"""
    session_id = request.COOKIES.get('session_id')
    if session_id:
        session_manager.create_session(session_id, user_data)  # create_session also handles updates
        response.set_cookie('session_id', session_id, max_age=3600*24)
        return response
    return None

def update_session(user_id: int, user_name: str, user_data):
    session_id = hashlib.sha256(f"{user_name}{user_id}".encode()).hexdigest()
    session_manager.create_session(session_id, user_data)
    print("Updated the Session for User: ", user_name)

def get_session(user_id: int, user_name: str):
    session_id = hashlib.sha256(f"{user_name}{user_id}".encode()).hexdigest()
    session = session_manager.get_session(session_id)
    if session:
        print("Getting user session for User: ", user_name)
        return session
    return None
    

def get_ten_digit_int_id(user_identifier_string: str) -> int:
    """Converts a user identifier string into a large integer using SHA-256."""
    # Hash the string using SHA-256
    hash_bytes = hashlib.sha256(user_identifier_string.encode('utf-8')).digest()
    # Convert the hash bytes to an integer
    user_int_id = int.from_bytes(hash_bytes, byteorder='big')
    return user_int_id % 10**10

def get_user_ids_from_name(user_names: list) -> list:
    user_ids = []
    for name in user_names:
        user_data = session_manager.get_user_by_name(name)
        if user_data:
            user_ids.append(user_data['user_id'])
    return user_ids

def verify_user(user_id: int, accumulator: int) -> bool:
    witness = accumulator.prove_membership(user_id)
    nonce = accumulator.get_nonce(user_id)
    if witness is None or nonce is None:
        return False
    return RsaAccumulator.verify_membership(accumulator.current_accumulator_value, user_id, nonce, witness, accumulator.n, 256)

def initialize_accumulator(accumulator : tuple) -> RsaAccumulator:
    """Initialize the accumulator with values from the contract."""
    sol_a0 = accumulator[0]
    sol_N = accumulator[1]
    sol_user_ids = accumulator[2]  # This will be an empty list []
    sol_nonces = accumulator[3] 
    data = {}
    for i in range(len(sol_user_ids)):
        data[sol_user_ids[i]] = sol_nonces[i]
        
    print("------------------Solidity Accumulator Values ------------------")
    print(f"a0: {sol_a0}, N: {sol_N}")
    print("---------------------------------------------------------------")
    print(data)
    
    # Initialize the accumulator with the values from the contract
    acc = RsaAccumulator(a0=sol_a0, N=sol_N, data=data)
    
    return acc

def getKey(): #generating key with PBKDF2 for AES
    password = "s3cr3t*c0d3"
    passwordSalt = '76895'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encrypt(plaintext): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(getKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decrypt(enc): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(getKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def fileExists(file_hash: int, user_id : int) -> bool:
    """Check if a file exists in the Accumulator of any direct or indirect access."""
    _, direct_acc = readDetails('direct', user_id)
    _, indirect_acc = readDetails('indirect', user_id)
    
    if verify_user(file_hash, direct_acc) or verify_user(file_hash, indirect_acc):
        return True
    return False

def user_to_save(selected_users: list, contract_type : str, filename: str, role: str) -> dict:
    '''
        Give the user with the selected role access to the file.
    '''
    # if contract_type == 'direct_access':
    #     user[contract_type][role].clear()
    # else :
    #     user[contract_type]['user_ids'].clear()
    print ("--- Saving Users ---")
    file_hash = get_ten_digit_int_id(filename)
    user_ids = get_user_ids_from_name(selected_users)
    
    print("User IDs: ", user_ids)
    filtered_user_ids = {}
    
    for i in range(len(user_ids)):
        user = get_session(user_ids[i], selected_users[i])
        if user and not fileExists(file_hash, user_ids[i]):            
            if contract_type == 'direct_access':
                filtered_user_ids[selected_users[i]] = user_ids[i]
                acc = user['ds_file_acc']
                acc.add(file_hash)
                user['ds_file_acc'] = acc
            else :
                filtered_user_ids[selected_users[i]] = user_ids[i]
                acc = user['ids_file_acc']
                acc.add(file_hash)
                user['ids_file_acc'] = acc
            update_session(user_ids[i], selected_users[i], user)

    return filtered_user_ids


def connecting_blockchain():
    global blockchain_address, deployed_contract_address, contract_file
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = contract_file #Blockchain contract file
    deployed_contract_address = deployed_contract_address #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    return web3, contract


def readDetails(contract_type : str, user_id: int = None):
    details = ""
    
    print("="*20)
    print("Reading data from blockchain for: ", contract_type)
    print("="*20)
    
    web3 , contract = connecting_blockchain()
    
    if contract_type == 'signup':
        details += contract.functions.getDataUser(user_id).call()
        print("Details from readDetails : ", details)
        acc_solidity_tuple = contract.functions.getAccumulator('owner', user_id).call()
        # Initialize the accumulator with the values from the contract
        acc = initialize_accumulator(acc_solidity_tuple)
        print("Accumulator from readDetails : ", acc.get_elements(), acc.get_nonces())
        
        return acc
        
    if contract_type == 'direct':
        details += contract.functions.getDirectSharing(user_id).call()
        acc_solidity_tuple = contract.functions.getAccumulator('direct', user_id).call()
        acc = initialize_accumulator(acc_solidity_tuple)
        
        return details, acc
    
    if contract_type == 'indirect':
        details += contract.functions.getInDirectSharing(user_id).call()   
        acc_solidity_tuple = contract.functions.getAccumulator('indirect', user_id).call()
        acc = initialize_accumulator(acc_solidity_tuple)
        
        return details, acc

def saveDataBlockChain(request, currentData : str = None, contract_type : str = None, users: dict = None, data_type: str=None, user_data: dict = None):
    details = ""    
    user = get_user_session(request) or user_data
    user_id = user['user_id']
    user_type = user['usertype']

    acc = user['acc']
    
    print("="*30)
    print("Saving data to blockchain...")
    print("="*30)
    
    web3, contract = connecting_blockchain()
    
    
    # readDetails(contract_type)
    
    if contract_type == 'signup':
        details+=currentData if currentData else ""
        print("Details: ", details)
        msg = contract.functions.createDataUser(user_id, user_type, details).transact({'from': web3.eth.defaultAccount})
        tx_receipt = web3.eth.wait_for_transaction_receipt(msg)
        
        # Now add the acc value.
        acc.add(user_id)
        msg = contract.functions.setAccumulator(user_type, user_id, acc.current_accumulator_value, acc.n, acc.get_elements(), acc.get_nonces()).transact({'from': web3.eth.defaultAccount})
        tx_receipt = web3.eth.wait_for_transaction_receipt(msg)
        return acc
    
    if contract_type == 'direct':
        details+=currentData if currentData else ""
        for user_name, user_id in users.items():
            existing_details, _ = readDetails('direct', user_id)
            ds_acc = get_session(user_id, user_name)['ds_file_acc']
            if existing_details and not data_type:
                details += existing_details
            msg = contract.functions.setDirectSharing(user_id, details).transact({'from': web3.eth.defaultAccount})
            tx_receipt = web3.eth.wait_for_transaction_receipt(msg)
            
            msg = contract.functions.setAccumulator('direct', user_id, ds_acc.current_accumulator_value, ds_acc.n, ds_acc.get_elements(), ds_acc.get_nonces()).transact({'from': web3.eth.defaultAccount})
            tx_receipt = web3.eth.wait_for_transaction_receipt(msg)
            
    if contract_type == 'indirect':
        details+=currentData if currentData else ""
        
        for user_name, user_id in users.items():
            existing_details , _ = readDetails('indirect', user_id)
            ids_acc = get_session(user_id, user_name)['ids_file_acc']
            if existing_details and not data_type:
                details += existing_details
            msg = contract.functions.setInDirectSharing(user_id, details).transact({'from': web3.eth.defaultAccount})
            tx_receipt = web3.eth.wait_for_transaction_receipt(msg)
            
            msg = contract.functions.setAccumulator('indirect', user_id, ids_acc.current_accumulator_value, ids_acc.n, ids_acc.get_elements(), ids_acc.get_nonces()).transact({'from': web3.eth.defaultAccount})
            tx_receipt = web3.eth.wait_for_transaction_receipt(msg)
            
            
    return details

def find_indirect_recipients(user_names: list, filename: str):
    """Find users who received indirect access to a file through a specific user"""
    indirect_users = {}
    
    # Get all sessions to examine indirect access records
    all_sessions = session_manager.get_all_sessions()
    
    for session in all_sessions.values():
        if session['usertype'] != 'Data Owner':
            details, _ = readDetails('indirect', session['user_id'])
            indirect_users[session['user_id']] = {}
            if details != "":
                arr = details.split("\n")
                for i in range(len(arr)):
                    array = arr[i].split("#")
                    if len(array) != 6:
                        continue
                    if array[1] == filename and array[5] in user_names:
                        indirect_users[session['user_id']][session['username']] = array[5]
    
    return indirect_users

def file_name_access_users_mapping(user_ids: int, user_name: str) -> dict:
    session_data = session_manager.get_all_sessions()
    mapping ={}
    # filename_access_user_id_mapping = {}
    for user in session_data.values():
        if user['user_id'] in user_ids:
            details, _ = readDetails('direct', user['user_id'])
            mapping[user['user_id']] = {}
            if details != "":
                arr = details.split("\n")
                for i in range(len(arr)):
                    array = arr[i].split("#")
                    if len(array)!=5:
                        continue
                    if array[0] == user_name and len(array) == 5:
                        mapping[user['user_id']][user['username']] = array[1]
                
    return mapping

def get_access_user_ids_by_username_or_user_id(user_name: str = None, user_id: int = None) -> list:
    session = session_manager.get_all_sessions()
    user_ids = []
    if user_name == None and user_id:
        user_name = [user['username'] for user in session.values() if user['user_id'] == user_id]
    for user in session.values():
        if user['usertype'] != 'Data Owner':
            details, _ = readDetails('direct', user['user_id'])
            if details != "":
                arr = details.split("\n")
                for i in range(len(arr)):
                    array = arr[i].split("#")
                    if len(array)!=5:
                        continue
                    if array[0] == user_name and user['user_id'] not in user_ids:
                        user_ids.append(user['user_id'])
    
    return user_ids

def RevokeUser(request):
    if request.method == 'GET':
        user = get_user_session(request)
        if not user or user['usertype'] != 'Data Owner':
            return render(request, 'Login.html', {'data': 'Please login first'})
            
        user_ids = get_access_user_ids_by_username_or_user_id(user['username'])
        print(user_ids)
        file_mapping = {}
        user_id_details_mapping= file_name_access_users_mapping(user_ids, user['username'])
        for user_id in user_ids:
            if user_id_details_mapping[user_id]:
                for user_name, filename in user_id_details_mapping[user_id].items():
                    if filename not in file_mapping:
                            file_mapping[filename] = {
                                'name': filename,
                                'value': filename,
                                'users': {}
                            }
                    # Add this user to the file's users dictionary
                    file_mapping[filename]['users'][user_id] = user_name
        
        file_names = list(file_mapping.values())
        print(file_names)
        context = {
            'files': file_names,
            'page_title': 'Revoke User Access'
        }
        return render(request, 'RevokeUser.html', context)

def RevokeUserAction(request):
    print("="*50)
    print("RevokeUserAction")
    print("="*50)
    if request.method == 'POST':
        user = get_user_session(request)
        if not user:
            return render(request, 'Login.html', {'data': 'Please login first'})
            
        filename = request.POST.get('file_name')
        user_ids_to_revoke = request.POST.getlist('user_ids')
        user_ids_to_revoke = [int(id) for id in user_ids_to_revoke]
        user_names_to_revoke = session_manager.get_usernames_by_ids(user_ids_to_revoke)
        
        print("File Selected: ", filename)
        print("Users to Revoke: ", user_ids_to_revoke)
        if not filename or not user_ids_to_revoke:
            return render(request, 'RevokeUser.html', {'error': 'Please select both file and users'})
            
        # direct_access = user['direct_access']
        file_hash = get_ten_digit_int_id(filename)
        users = {user_names_to_revoke[i] : user_ids_to_revoke[i] for i in range(len(user_names_to_revoke))}
        indirect_users = find_indirect_recipients(user_names_to_revoke, filename)
        
        for i in range(len(user_ids_to_revoke)):
            print(f"Revoking access for {user_names_to_revoke[i]} to {filename} given by {user['username']}")
            details, ds_acc = readDetails('direct', user_ids_to_revoke[i])
            user_to_revoke = get_session(user_ids_to_revoke[i], user_names_to_revoke[i])
            new_arr = []
            print(details)
            if details:
                arr = details.split("\n")
                
                for j in range(len(arr)):
                    array = arr[j].split("#")
                    if len(array)!=5:
                        continue
                    if array[1] == filename:
                        continue
                    new_arr.append(arr[j])
                        
            if verify_user(file_hash, ds_acc):
                ds_acc.delete(file_hash)
                user_to_revoke["ds_file_acc"] = ds_acc
                update_session(user_ids_to_revoke[i], user_names_to_revoke[i], user_to_revoke)
                
            print(new_arr)
            data = ""
            if new_arr:
                data = "\n".join(new_arr) + "\n"
            print(data)
            #! Individually saving for each user.
            saveDataBlockChain(request=request,currentData=data, contract_type="direct", users={user_names_to_revoke[i]: user_ids_to_revoke[i]}, data_type='revoke')
            
        
            for ind_user_id, data in indirect_users.items():
                if data :
                    for ind_user_name, d_user_name in data.items():
                        print(f"Cascading revocation: Removing {filename} access for {ind_user_name} granted by {d_user_name}")
                        details, ids_acc = readDetails('indirect', ind_user_id)
                        indirect_user = get_session(ind_user_id, ind_user_name)
                        new_arr = []
                        if details:
                            arr = details.split("\n")
                            for j in range(len(arr)):
                                array = arr[j].split("#")
                                if len(array)!=6:
                                    continue
                                if array[1] == filename and array[5] == d_user_name:
                                    continue
                                new_arr.append(arr[j])
                        if verify_user(file_hash, ids_acc):
                            ids_acc.delete(file_hash)
                            indirect_user["ids_file_acc"] = ids_acc
                            update_session(ind_user_id, ind_user_name, indirect_user)
                        data = ""
                        if new_arr:
                            data = "\n".join(new_arr) + "\n"
                        saveDataBlockChain(request=request,currentData=data, contract_type="indirect", users={ind_user_name: ind_user_id}, data_type='revoke')

        context = {
            'data': f'Successfully revoked access for selected users from file: {filename}'
        }
        return render(request, 'DataOwnerScreen.html', context)

def Download(request):
    if request.method == 'GET':
        filename = request.GET['t1']
        hashcode = request.GET['t2']
        
        try:
            # Use direct HTTP POST request to IPFS API
            import requests
            
            # Make a direct POST request to the IPFS API
            url = "http://127.0.0.1:5001/api/v0/cat"
            params = {"arg": hashcode}
            response = requests.post(url, params=params)
            response.raise_for_status()  # Raise exception for HTTP errors
            
            content_bytes = response.content
            print(f"Retrieved {len(content_bytes)} bytes from IPFS")
            
            # Skip pickle.loads and directly decrypt the content
            # The upload process uses pickle.dumps(encrypt(myfile)), so we need to unpickle first
            try:
                # First try standard approach - unpickle then decrypt
                encrypted_content = pickle.loads(content_bytes)
                print(f"Successfully unpickled data, size: {len(encrypted_content) if isinstance(encrypted_content, bytes) else type(encrypted_content)}")
                
                # encrypted_content = pickle.loads(encrypted_content)
                
                # Decrypt the content
                decrypted_content = decrypt(encrypted_content)
                
                # Set the correct MIME type
                mime_type, _ = mimetypes.guess_type(filename)
                if not mime_type:
                    # Try to guess MIME type from file extension if mimetypes fails
                    extension = filename.split('.')[-1].lower() if '.' in filename else ''
                    if extension in ['jpg', 'jpeg', 'png', 'gif']:
                        mime_type = f'image/{extension}'
                    elif extension in ['pdf']:
                        mime_type = 'application/pdf'
                    else:
                        mime_type = 'application/octet-stream'  # Default
                
                print(f"Using MIME type: {mime_type}")
                    
                # Create and return the response
                http_response = HttpResponse(decrypted_content, content_type=mime_type)
                http_response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return http_response
                
            except Exception as e:
                print(f"Error in standard processing: {str(e)}")
                
                # If the standard way fails, try alternative approaches:
                # Try direct decryption (in case the content was only encrypted and not pickled)
                try:
                    print("Attempting alternative 1: direct decryption")
                    decrypted_content = decrypt(content_bytes)
                    http_response = HttpResponse(decrypted_content, content_type='application/octet-stream')
                    http_response['Content-Disposition'] = f'attachment; filename="{filename}"'
                    return http_response
                except Exception as e2:
                    print(f"Alternative 1 failed: {str(e2)}")
                    
                    # As a last resort, try to serve the raw content
                    print("Attempting alternative 2: raw content")
                    http_response = HttpResponse(content_bytes, content_type='application/octet-stream')
                    http_response['Content-Disposition'] = f'attachment; filename="{filename}"'
                    return http_response
            
        except requests.exceptions.RequestException as e:
            print(f"IPFS API request error: {str(e)}")
            return HttpResponse(f"Error accessing IPFS: {str(e)}", status=500)
        except Exception as e:
            print(f"Unexpected error: {str(e)}, {type(e)}")
            return HttpResponse(f"Error downloading file: {str(e)}", status=500)
        
def AccessShareData(request):
    if request.method == 'GET':
        user = get_user_session(request)
        user_id = user['user_id']
        direct_details, _ = readDetails('direct', user_id)
        indirect_details, _ = readDetails('indirect', user_id)
        details = direct_details + "\n" + indirect_details
        
        print("="*20)
        print("Accessing Shared Data")
        print("="*20)
        arr = details.split("\n")
        shared_files = []
        
        for i in range(len(arr)):
            array = arr[i].split("#")
            # Only add valid entries with all required fields
            if len(array) == 5 or len(array) == 6:
                shared_files.append({
                    'owner_name': array[0],
                    'filename': array[1],
                    'hash_value': array[2],
                    'access_users': array[3],
                    'upload_datetime': array[4],
                })
        
        context = {
            'shared_files': shared_files,
            'page_title': 'Access Shared Data'
        }
        return render(request, 'AccessShareData.html', context)

def Graph(request):
    if request.method == 'GET':
        user = get_user_session(request)
        print(user['runtime_data'])
        runtime_data = user['runtime_data']
        if not runtime_data:
            # If no data, you might want to render the page with a message
            context = {'graph_title': "Computation Graph", 'graph_error': "No data available to generate graph."}
            return render(request, 'DataUserScreen.html', context)

        height = []
        bars = []
        try:
            for i in range(len(runtime_data)):
                arr = runtime_data[i].split(",")
                if len(arr) == 2:
                    bars.append(arr[0])
                    height.append(float(arr[1]))
                else:
                    print(f"Warning: Skipping malformed runtime_data entry: {runtime_data[i]}")
            
            if not bars or not height: # Check if after processing, we still have data
                context = {'graph_title': "Computation Graph", 'graph_error': "Not enough valid data to generate graph after processing."}
                return render(request, 'DataUserScreen.html', context)

        except ValueError as e:
            print(f"Error processing runtime_data for graph: {e}")
            context = {'graph_title': "Computation Graph", 'graph_error': f"Error processing data for graph: {e}"}
            return render(request, 'DataUserScreen.html', context)
        except Exception as e: # Catch any other unexpected errors
            print(f"Unexpected error processing runtime_data for graph: {e}")
            context = {'graph_title': "Computation Graph", 'graph_error': f"An unexpected error occurred: {e}"}
            return render(request, 'DataUserScreen.html', context)

        # --- Matplotlib plotting ---
        fig, ax = plt.subplots(figsize=(10, 6)) # Adjust figsize as needed
        y_pos = np.arange(len(bars))
        ax.bar(y_pos, height, color='skyblue') # Added color for better appearance
        ax.set_xticks(y_pos)
        ax.set_xticklabels(bars, rotation=45, ha="right") # Rotate labels for better readability
        ax.set_ylabel('Time (seconds)')
        ax.set_xlabel('Filename / Operation')
        ax.set_title("Blockchain Total Computation Time")
        
        plt.tight_layout() # Adjust layout to prevent labels from overlapping

        # Save the plot to a BytesIO buffer
        buf = io.BytesIO()
        fig.savefig(buf, format='png', bbox_inches='tight') # Added bbox_inches
        plt.close(fig) # Close the figure to free memory
        buf.seek(0)
        
        # Encode image to base64 string
        image_png = buf.getvalue()
        buf.close() # Close the buffer
        graph_b64 = base64.b64encode(image_png).decode('utf-8')
        
        # Pass the base64 image string to the template
        context = {
            'graph_title': "Computation Graph", # You can use this in your template's h2
            'graph_image_b64': graph_b64
        }
        return render(request, 'DataUserScreen.html', context)
    else:
        # Handle other request methods if necessary, or redirect
        return HttpResponse("Invalid request method for Graph.", status=405)

def get_data_for_indirect_access(filename: str, user_id: int) -> str:
    data = ""
    details, _ = readDetails('direct', user_id)
    if details == "":
        return None
    arr = details.split("\n")
    for i in range(len(arr)):
        array = arr[i].split("#")
        if len(array)!=5:
                continue
        if array[1] == filename and len(array) == 5:
            data = array[0] + "#" + array[1] + "#" + array[2] + "#" + array[3] + " "
    return data
    

def IndirectAccessAction(request):
    print("------------------------Indirect Access Action------------------------")
    if request.method == 'POST':
        filename = request.POST.get('t1')
        selected_users = request.POST.getlist('t2')  # Get list of selected usernames
        user = get_user_session(request)
        now = datetime.datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        role = 'Doctor' if user['usertype'] == 'Researcher' else 'Researcher'
        data = get_data_for_indirect_access(filename, user['user_id'])
        if not data:
            return render(request, 'IndirectAccess.html', {'error': 'File not found or no access to the file'})
        
        # data = f"{user['username']}#{filename}#{hashcode}#{role}#{current_time}\n"
        
        # Get user_ids for selected users
        data = data + role + "#" + current_time + "#" + user['username'] +"\n"
        print("Data to be stored in blockchain: ", data)
        print("Giving Indirect Access to: ", selected_users)
        
        filtered_user_ids = user_to_save(selected_users, 'indirect_access', filename, user['usertype'])
        # Save data to blockchain for indirect access
        start = time.time()
        saveDataBlockChain(request, data, "indirect", filtered_user_ids)
        end = time.time()
        
        for name, id in filtered_user_ids.items():
            i_user = get_session(id, name)
            i_user['runtime_data'].append("Indirect Access "+filename+","+str(end-start))
            update_session(id, name, i_user)
        
        output = f"Indirect access granted to {len(selected_users)} users for file: {filename}"
        context = {'message': output,
                   'message_type': 'success'}
        
        return save_user_session(request, 'DataUserScreen.html', context, user)


def IndirectAccess(request):
    if request.method == 'GET':
        print("--------------------------------Indirect Access------------------------------")
        user = get_user_session(request)
        if not user or user['usertype'] == 'Data Owner':
            return render(request, 'Login.html', {'data': 'Please login first'})
            
        # Should not give indirect access to things which the current user already has indirect access to
        details, _ = readDetails('direct', user['user_id'])
        print(details)
        files = []
        if len(details) == 0 or details[0]=='':
            context = {
                'files': files,
                'user_type': user['usertype']
            }
            return render(request, 'IndirectAccess.html', context)
        arr = details.split("\n")
        print("Code came here")
        print(arr)
        # Get available files for the user
        for i in range(len(arr)):
            array = arr[i].split("#")
            if len(array)!=5:
                        continue
            if array[1] not in files:
                files.append({
                    'name': array[1],
                    'value': array[1]
                })
        
        # Get users of the opposite role
        target_role = 'Doctor' if user['usertype'] == 'Researcher' else 'Researcher'
        users = session_manager.get_users_by_role(target_role)
        
        context = {
            'files': files,
            'user_type': user['usertype'],
            'users': users  # Add users to context
        }
        return render(request, 'IndirectAccess.html', context)

def get_users_by_role(request):
    if request.method == 'GET':
        role = request.GET.get('role')
        users_list = session_manager.get_users_by_role(role)
        return JsonResponse(users_list, safe=False)

def UploadImageAction(request):
    if request.method == 'POST':
        global give_access
        user = get_user_session(request)
        if user['usertype'] != 'Data Owner':
            return render(request, 'Login.html', {'data': 'Please login first'})
        print("------------------------Upload Image Action------------------------")
        print(user)
        
        # Get the role and selected usernames
        role = request.POST.get('role')
        selected_users = request.POST.getlist('t2')
        
        # user_ids = get_user_ids_from_name(selected_users)
        filename = request.FILES['t1'].name
        myfile = request.FILES['t1'].read()
        myfile = encrypt(myfile)
        myfile = pickle.dumps(myfile)
        try:
            import requests
            import io
            
            # Create a file-like object from the pickled bytes
            file_obj = io.BytesIO(myfile)
            
            # Make a direct POST request to the IPFS API
            url = "http://127.0.0.1:5001/api/v0/add"
            files = {'file': ('file', file_obj)}
            response = requests.post(url, files=files)
            response.raise_for_status()  # Raise exception for HTTP errors
            
            # Parse the response JSON to get the hash
            result = response.json()
            hashcode = result['Hash']
            print(f"Successfully uploaded file to IPFS with hash: {hashcode}")
            
            now = datetime.datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            
            data = f"{user['username']}#{filename}#{hashcode}#{role}#{current_time}\n"

            print("Data to be stored in blockchain: ", data)
            
            filtered_user_ids = user_to_save(selected_users, 'direct_access', filename, role)
            
            
            start = time.time()
            saveDataBlockChain(request, data, 'direct', filtered_user_ids)
            end = time.time()
            
            d_user = {}
            for name, id in filtered_user_ids.items():
                d_user = get_session(id, name)
                if d_user:
                    d_user['runtime_data'].append(f"Direct Access {filename},{str(end-start)}")
                    update_session(id, name, d_user)
            
            print ("\n------------------------Runtime Data------------------------\n")
            print('runtime_data:', d_user['runtime_data'])
            print ("\n------------------------------------------------------------\n")
            
            output = 'Given medical file saved in cloud with hash code.<br/>'+str(hashcode)
            context= {'data':output}
            # Updating the cookie with the new user data
            return save_user_session(request, 'DataOwnerScreen.html', context, user)
        except requests.exceptions.RequestException as e:
                print(f"IPFS API request error: {str(e)}")
                context = {'data': f"Error uploading to IPFS: {str(e)}"}
                return render(request, 'DataOwnerScreen.html', context)
        except Exception as e:
            print(f"Unexpected error during upload: {str(e)}")
            context = {'data': f"Error uploading file: {str(e)}"}
            return render(request, 'DataOwnerScreen.html', context)

def UploadImage(request):
    if request.method == 'GET':
        return render(request, 'UploadImage.html', {})
    
def index(request):
    if request.method == 'GET':
        return render(request, 'index.html', {})

def Login(request):
    if request.method == 'GET':
        return render(request, 'Login.html', {})

def Signup(request):
    if request.method == 'GET':
        return render(request, 'Signup.html', {})

def LoginAction(request):
    if request.method == 'POST':
        global username, access_user, user_id
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        usertype = request.POST.get('t3', False)
        
        
        user_info = username+password+usertype + salt
        user_id = get_ten_digit_int_id(user_info)
        
        acc = readDetails('signup', user_id)
        status = "none"
        
        if verify_user(user_id, acc):
            status = "Welcome " + username
            user_data = {
                'username': username,
                'usertype': usertype,
                'user_id': user_id,
                'acc': acc,
                'runtime_data': [],  # Initialize empty runtime_data array for this session
                'login_time': time.time()
            }
            # Create response object based on user type
            if usertype == 'Data Owner':
                # response = render(request, 'DataOwnerScreen.html', {'data': status})
                return save_user_session(request, 'DataOwnerScreen.html', {'data' : status}, user_data)
            else :
                _, ds_acc = readDetails('direct', user_id)
                #! Only storing direct access file acc value for each data user.
                user_data['ds_file_acc'] = ds_acc
                
                _, ids_acc = readDetails('indirect', user_id)
                #! Only storing indirect access file acc value for each data user.
                user_data['ids_file_acc'] = ids_acc
                
                print(user_data)
                # response = render(request, 'DataUserScreen.html', {'data': status})
                return save_user_session(request, 'DataUserScreen.html',{'data' : status}, user_data)
        else:
            context = {'data': 'login failed'}
            return render(request, 'Login.html', context)

        
def SignupAction(request):
    print("------------------------Signup Action------------------------")
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        usertype = request.POST.get('t3', False)
        
        user_info = username+password+usertype + salt
        user_id = get_ten_digit_int_id(user_info)
        password = password.encode('utf-8').hex()
        
        acc = readDetails('signup', user_id)
        print("Accumulator we get in SignupAction: ", acc)
        

        if verify_user(user_id,acc):
            context = {"data": username+" already exists"}
            return render(request, 'Login.html', context)
        details = ""
        data = f"{username}#{password}#{usertype}#"
        # Get the accumulator value from saveDataBlockChain.
        user_data = {
            'username': username,
            'usertype': usertype,
            'user_id': user_id,
            'acc': acc,
            'runtime_data': [],  # Initialize empty runtime_data array for this session
            'login_time': time.time()
        }
        
        if usertype != 'Data Owner' :
            _, ds_acc = readDetails('direct', user_id)
            print("Direct Access details: ", _)
            #! Only storing direct access file acc value for each data user.
            user_data['ds_file_acc'] = ds_acc
            
            _, ids_acc = readDetails('indirect', user_id)
            print("Indirect Access details: ", _)
            #! Only storing indirect access file acc value for each data user.
            user_data['ids_file_acc'] = ids_acc
        
        
        context = {"data":"Signup process completed and record saved in Blockchain"}
        html_page = 'DataOwnerScreen.html' if usertype == 'Data Owner' else 'DataUserScreen.html'
        
        response =  save_user_session(request,html_page, context, user_data)
        
        print ("User Data: ", user_data)
        user_data['acc'] = saveDataBlockChain(request=request, currentData=data, contract_type='signup', user_data=user_data)
        
        update_cookie(request, response, user_data)
        
        return response

def Logout(request):
    if request.method == 'GET':
        # Get session ID from cookie
        session_id = request.COOKIES.get('session_id')
        
        # Remove user data from session manager if exists
        # if session_id:
        #     session_manager.delete_session(session_id)
        
        print("-------------------------------LOGOUT-------------------------------")
        response = render(request, 'Login.html', {'data': 'Logged out successfully'})
        response.delete_cookie('session_id')
        return response

print(session_manager.get_all_sessions())