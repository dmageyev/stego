import re

def encode_message(text, message):
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    sentences = re.split(r'(\.|\!|\?)', text)
    encoded_text = ""
    
    message_index = 0
    for i in range(0, len(sentences) - 1, 2):
        if message_index < len(binary_message):
            if binary_message[message_index] == '1':
                sentences[i+1] += "  "  # Два проб?ли (прихований б?т 1)
            else:
                sentences[i+1] += " "   # Один проб?л (прихований б?т 0)
            message_index += 1
        encoded_text += sentences[i] + sentences[i+1]
    
    if len(sentences) % 2 != 0:
        encoded_text += sentences[-1]
    
    return encoded_text

def decode_message(encoded_text):
    sentences = re.split(r'([.!?])(\s*)', encoded_text)
    binary_message = ""
    
    for i in range(0, len(sentences)-1, 3):
        if sentences[i+2].endswith("   "):
            binary_message += '1'
        elif sentences[i+2].endswith("  "):
            binary_message += '0'
    
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))
    
    return message

def calculate_capacity(text):
    sentences = re.split(r'(\.|\!|\?)', text)
    capacity = len(sentences) // 2
    return capacity

# Тестування
cover_text = "Hello world. How are you? This is a test! Stenography is fun. Hello world. How are you? This is a test! Stenography is fun. Hello world. How are you? This is a test! Stenography is fun."
hidden_message = "Hi"

capacity = calculate_capacity(cover_text)
print(f"Container Capacity: {capacity} bits")

encoded_text = encode_message(cover_text, hidden_message)
print("Encoded Text:")
print(encoded_text)

decoded_message = decode_message(encoded_text)
print("\nDecoded Message:")
print(decoded_message)
