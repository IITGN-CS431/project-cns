import argparse
import os
import sys
from cryptography.fernet import Fernet
import bcrypt
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Function to derive the encryption key from the password
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to load the hashed password from the log file
def load_hashed_password(log):
    with open(log, 'rb') as f:
        hashed_password = f.readline().strip()
    return hashed_password

# Function to authenticate users based on the token in the log file
def authenticate(log, auth_token):
    hashed_password = load_hashed_password(log)
    if bcrypt.checkpw(auth_token.encode(), hashed_password):
        return True
    else:
        return False

# Function to append a new log entry (encrypted)
def append_log(log, timestamp, entry, key):
    try:
        cipher_suite = Fernet(key)
        encrypted_entry = cipher_suite.encrypt(f"{timestamp}, {entry}".encode())
        with open(log, 'a') as f:
            f.write(encrypted_entry.decode() + "\n")
    except Exception as e:
        print("Error appending log entry.")

# Function to check the log state for consistency and last entry status
def validate_log(log, timestamp, user, role, key):
    if not os.path.exists(log):
        return True, None  # If the log does not exist, it's valid

    cipher_suite = Fernet(key)
    with open(log, 'r') as f:
        lines = f.readlines()[1:]  # Skip the first line (token)
        last_event_info = None
        last_timestamp = -1

        # Find the last log entry for the specified user
        for line in lines:
            decrypted_entry = cipher_suite.decrypt(line.strip().encode()).decode()
            entry = decrypted_entry.split(", ")
            if len(entry) >= 5:  # Ensure sufficient entry length
                event_timestamp = int(entry[0])
                if event_timestamp > last_timestamp:
                    last_timestamp = event_timestamp # Update the last timestamp found
                if entry[2] == user and entry[1] == role:
                    last_event_info = (entry[3], entry[4])  # (event type, room)

        # Ensure the new timestamp is greater than the last timestamp
        if int(timestamp) <= last_timestamp:
            return False, None
        return True, last_event_info  # If found, return last event info

# Function to check entry and exit restrictions
def check_entry_exit_restrictions(current_room, args):
    if args.A:  # Arrival event
        if current_room == 'None' and args.R is None:
            return True, None
        if current_room == 'campus' and args.R is not None:
            return True, None
        if current_room != 'campus' and args.R is not None:
            return False, "invalid: Are you on campus? You must leave the room first before entering another room."
        if current_room != 'campus' and args.R is None:
            return False, "invalid: You are in a room. First leave the room."
        if current_room == 'campus' and args.R is None:
            return False, "invalid: Already on campus."
    elif args.L:  # Departure event
        if current_room == 'campus' and args.R is None:
            return True, None
        if current_room != 'campus' and args.R is None:
            return False, "invalid: Either first leave the room or You have already left the campus."
        if current_room == args.R and args.R is not None:
            return True, None
        if current_room != 'campus' and args.R is not None:
            return False, "invalid: Leave the room you are in first."
        if current_room != args.R and args.R is not None:
            return False, "invalid: Must have been in the room to leave it."

    return True, None

def normalize_room_id(room_id):
    # Convert the room ID to an integer to drop leading zeros
    normalized_id = str(int(room_id))
    return normalized_id

# Function to process a batch file
def process_batch_file(batch_file):
    if not os.path.exists(batch_file):
        print("invalid: Batch file does not exist.")
        sys.exit(255)

    with open(batch_file, 'r') as f:
        line_number = 0  # Track line numbers for better error reporting
        for line in f:
            line_number += 1
            args = line.strip().split()
            if args:
                log_file = args[-1]  # Get the log file from the last argument
                try:
                    process_args(args[:-1] + [log_file])  # Process the current line
                except Exception as e:
                    print(f"Error processing line {line_number}: {e}")  # Print error and continue

# Main function to process command-line arguments and append log entry
def process_args(args=None):
    parser = argparse.ArgumentParser(description="Append new log entry.")
    parser.add_argument("-T", required=True, type=int, help="Timestamp for the event")
    parser.add_argument("-K", required=True, help="Authentication token")
    parser.add_argument("-E", help="Employee name")
    parser.add_argument("-G", help="Guest name")
    parser.add_argument("-A", action="store_true", help="Arrival event")
    parser.add_argument("-L", action="store_true", help="Departure event")
    parser.add_argument("-R", type=str, help="Room ID")
    parser.add_argument("log", help="Path to the log file")

    args = parser.parse_args(args)

    if not ( 0 < args.T <= 1073741823 ):
        raise ValueError("Timestamp cannot be zero.")

    # Ensure that the room ID is an integer between 0 and 1,073,741,823
    if args.R is not None:
        try:
            args.R = normalize_room_id(args.R)
            room_id = int(args.R)
            if room_id < 0 or room_id > 1073741823:
                raise ValueError("Invalid Room Number")
        except ValueError:
            raise ValueError("Invalid Room Number")
 
    # Ensure only one of -E or -G is specified
    if (args.E and args.G) or (not args.E and not args.G):
        raise ValueError("Specify either -E for employee or -G for guest, not both.")

    if not (args.A or args.L):
        raise ValueError("One of -A (arrival) or -L (departure) must be specified.")

    if args.A and args.L:
        raise ValueError("Specify either -A for arrival or -L for departure, not both.")
    
    #Ensure that args.E or args.G is alphabetical (a-z, A-Z)
    if args.E:
        if not args.E.isalpha():
            raise ValueError("Invalid Employee Name.")
    if args.G:
        if not args.G.isalpha():
            raise ValueError("Invalid Guest Name.")
    
    if not authenticate(args.log, args.K):
        raise ValueError("Authentication failed.")

    hashed_password = load_hashed_password(args.log)
    salt = hashed_password[:16]  # Use the first 16 bytes of the hashed password as the salt
    key = derive_key_from_password(args.K, salt)

    user = args.E if args.E else args.G
    role = "employee" if args.E else "guest"
    is_valid, last_event = validate_log(args.log, args.T, user, role, key)

    if not is_valid:
        raise ValueError("Invalid log state.")

    if last_event:
        last_event_type, last_room = last_event[0], last_event[1]
        if last_event_type == 'arrival':
            current_room = last_room
        elif last_event_type == 'departure' and last_room != 'campus':
            current_room = 'campus'
        else:
            current_room = 'None'
    else:
        current_room = 'None'

    # Check entry and exit restrictions
    is_allowed, error_message = check_entry_exit_restrictions(current_room, args)
    if not is_allowed:
        raise ValueError(error_message)

    event = f"{role}, {user}, {'arrival' if args.A else 'departure'}, {args.R if args.R is not None else 'campus'}"

    append_log(args.log, args.T, event, key)
    print("Log entry added successfully.")

if __name__ == "__main__":
    try:
        if "-B" in os.sys.argv:
            batch_index = os.sys.argv.index("-B") + 1
            batch_file = os.sys.argv[batch_index]
            process_batch_file(batch_file)
        else:
            process_args()
    except Exception as e:
        print(f"Error: {str(e)}")
