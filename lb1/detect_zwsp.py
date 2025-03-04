# Detector for Zero Width Space (ZWSP) & Zero Width Non-Joiner (ZWNJ) Steganography
# Works in Kali Linux
# Author Ageyev D.V.

import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Zero Width Steganography Detector")
    parser.add_argument("input_text_file", help="Input text file")
#   parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    args = parser.parse_args()
	
    with open(args.input_text_file, "r") as f:
        text = f.read()
    invisible_chars = ["\u200B", "\u200C", "\u200D", "\uFEFF"]
    if any(char in text for char in invisible_chars):
        print("!!! Hidden symbols found !!!")
    else:
        print("--- No hidden characters found ---")
        
