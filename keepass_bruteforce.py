import re
from pykeepass import PyKeePass
import exrex
import logging

# Set up logging configuration
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('log.txt'),
                        logging.StreamHandler()
                    ])

def append_to_file(message, file_name):
    with open(file_name, 'a') as f:
        f.write(f"{message}\n")

def generate_passwords_from_regex(patterns):
    passwords = set()  # Initialize as a set
    for pattern in patterns:
        matches = set(exrex.generate(pattern))
        passwords.update(matches)  # Update the set with the new matches
    logging.info(f"Generated a total of {len(passwords)} unique passwords from regex patterns.")
    return list(passwords)  # Convert the set to a list before returning

def read_exclude_list_from_file(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def filter_excluded_passwords(passwords, exclude_strings):
    exclude_strings_set = set(exclude_strings)  # Convert to set for O(1) lookups
    passwords = [password for password in passwords if password not in exclude_strings_set]
    logging.info(f"After excluding, {len(passwords)} passwords remain.")
    return passwords

def unlock_keepass(database_path, password_list):
    for idx, password in enumerate(password_list, 1):  # Starts counting from 1
        try:
            kp = PyKeePass(database_path, password=password)
            logging.info(f"Successfully unlocked KeePass with password: {password} on attempt {idx}/{len(password_list)}")
            return True
        except Exception as e:  # Catch a specific exception if you know which one it is
            append_to_file(password, 'exclude_list.txt')
            logging.error(f"Failed to unlock KeePass with password: {password} on attempt {idx}/{len(password_list)}. Error: {e}")
            pass
    logging.error("Failed to unlock KeePass with all provided passwords.")
    return False

if __name__ == "__main__":
    regex_patterns = [
        
        r'test_pass', # example pattern
        r'\$password{2}' # 2nd regex pattern
        # Add more patterns as required
    ]
    
    # Read exclude list from text file
    exclude_list = read_exclude_list_from_file('exclude_list.txt')
    
    passwords = generate_passwords_from_regex(regex_patterns)
    passwords = filter_excluded_passwords(passwords, exclude_list)
    
    logging.info(f"Attempting to unlock database with {len(passwords)} passwords.")
    database_path = "ENTER_FILE_LOCATION_HERE>.kdbx" #update to your .kdbx file location
    unlock_keepass(database_path, passwords)
