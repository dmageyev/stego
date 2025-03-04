# Zero Width Space (ZWSP) & Zero Width Non-Joiner (ZWNJ) Steganography
# Works in Kali Linux
# Author Ageyev D.V.

import argparse
import hashlib

# Define zero-width characters
ZWSP = "\u200B"  # Zero Width Space
ZWNJ = "\u200C"  # Zero Width Non-Joiner
verb = False

# Hash function for password
def hash_password(password):
    result = hashlib.sha256(password.encode()).hexdigest()
    if verb:
        print(f"[INFO] Hashing password -> ", result)
    return result

# XOR function to encrypt/decrypt
def xor_encrypt_decrypt(data, key):
    if not key:
        return data  # No encryption if password is not provided
    if verb:
        print("[INFO] XOR input -> ", data)    
    key = hash_password(key)[:len(data)]  # Use only part of hash
    if verb:
        print("[INFO] Key cuted -> ", key)
    result = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key))    
    if verb:
        print(f"[INFO] XOR output -> ", result)
    result = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key))
    return result

# Encoding function
def encode_message(text, secret, password=None, verbose=False):
    if verbose:
        print("[INFO] Encrypting secret message..." if password else "[INFO] Encoding secret message without encryption...")
    secret = xor_encrypt_decrypt(secret, password)  # Encrypt secret if password provided
    binary_secret = ''.join(format(ord(c), '08b') for c in secret)  # Convert message to binary
    stego_text = text + " "  # Add a space as a delimiter
    
    if verbose:
        print("[INFO] Message converting to binary -> ", binary_secret)
    
    for bit in binary_secret:
        if bit == "0":
            stego_text += ZWSP  # Zero Width Space represents 0
        else:
            stego_text += ZWNJ  # Zero Width Non-Joiner represents 1
    
    if verbose:
        print("[INFO] Encoding completed successfully.")
    return stego_text

# Decoding function
def decode_message(stego_text, password=None, verbose=False):
    if verbose:
        print("[INFO] Extracting hidden message...")
    binary_secret = ""
    hidden_part = stego_text.split(" ")[-1]  # Extract hidden part after the space
    
    for char in hidden_part:
        if char == ZWSP:
            binary_secret += "0"
        elif char == ZWNJ:
            binary_secret += "1"
            
    if verbose:
        print("[INFO] Extracting binary -> ", binary_secret)
        
    secret_message = "".join(chr(int(binary_secret[i:i+8], 2)) for i in range(0, len(binary_secret), 8))
    decrypted_message = xor_encrypt_decrypt(secret_message, password)
    if verbose:
        print("[INFO] Decoding completed successfully.")
    return decrypted_message

# Read input from files
def read_file(filename):
    if verb:
        print("[INFO] Reading file ", filename)
    with open(filename, "r", encoding="utf-8") as file:
        return file.read().strip()

# Write output to file
def write_file(filename, content):
    if verb:
        print("[INFO] Writing file ", filename)
    with open(filename, "w", encoding="utf-8") as file:
        file.write(content)

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Zero Width Steganography Tool", 
            formatter_class=argparse.RawTextHelpFormatter,
            epilog='Encoding:\n\n    python zwsp.py e input.txt output.txt -s "hidden message" -p mypassword\n\n or \n\n' +
                    '    python zwsp.py e input.txt output.txt -f secret.txt -v -p mypassword \n\n' +
                    'Decoding: \n\n python zwsp.py d output.txt -p mypassword')
    subparsers = parser.add_subparsers(dest="mode", required=True)
    
    # Encoding parser
    encode_parser = subparsers.add_parser("e", help="Encode a secret message into a text file")
    encode_parser.add_argument("input_text_file", help="Input text file")
    encode_parser.add_argument("output_file", help="Output encoded file")
    encode_parser.add_argument("-p", "--password", help="Optional password for encryption")
    
    secret_group = encode_parser.add_mutually_exclusive_group(required=True)
    secret_group.add_argument("-s", "--secret", help="Secret message to hide")
    secret_group.add_argument("-f", "--secret_file", help="File containing secret message")
    
    group = encode_parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    group.add_argument("-q", "--quiet", action="store_true", help="Enable quiet mode")
    
        
    # Decoding parser
    decode_parser = subparsers.add_parser("d", help="Decode a secret message from a text file")
    decode_parser.add_argument("input_encoded_file", help="Input encoded file")
    decode_parser.add_argument("-p", "--password", help="Optional password for decryption")
    
    group = decode_parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    group.add_argument("-q", "--quiet", action="store_true", help="Enable quiet mode")
    
    args = parser.parse_args()
    
    verb = args.verbose
    
    if args.mode == "e":
        text = read_file(args.input_text_file)
        secret = args.secret if args.secret else read_file(args.secret_file)
        encoded_text = encode_message(text, secret, args.password, args.verbose)
        write_file(args.output_file, encoded_text)
        if not args.quiet:
            if args.verbose: 
                    print("")
            print("Encoded text saved to", args.output_file)
    
    elif args.mode == "d":
        encoded_text = read_file(args.input_encoded_file)
        decoded_secret = decode_message(encoded_text, args.password, args.verbose)
        if args.quiet:
            print(decoded_secret)
        else: 
            if args.verbose: 
                print("")
            print("Decoded Secret:", decoded_secret)
