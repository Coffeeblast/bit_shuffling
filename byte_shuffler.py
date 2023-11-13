import hashlib
import argparse
import getpass

def main():
    parser = argparse.ArgumentParser(description='Shuffles bytes in a file using a simple symmetric algorithm')

    # Adding arguments
    parser.add_argument('-i', '--input_file', help='Input filename', required=True)
    parser.add_argument('-o', '--output_file', help='Output filename', required=True)
    parser.add_argument('-d', '--decrypt_flag', action='store_true', help='If true, the decryption process is used, otherwise encryption.')

    args = parser.parse_args()

    # Accessing the arguments
    input_filename = args.input_file
    output_filename = args.output_file
    decrypt = args.decrypt_flag

    with open(input_filename, "rb") as fp:
        data = fp.read()

    password = getpass.getpass(prompt="Enter your password: ")

    if decrypt == "-e":
        output = decrypt(data, password)
    else:
        output = encrypt(data, password)        

    with open(output_filename, "wb") as fp:
        fp.write(output)

def negate(x):
    return ~x + 256

def encrypt(data, password):
    # xor --> 1 if data bit is different from mask, 0 if data bit is the same as mask
    mask = bytes.fromhex(hashlib.sha512(password.encode("utf-8")).hexdigest())
    return bytes(val ^ mask[i % len(mask)] for i, val in enumerate(data))

def decrypt(data, password):
    # inverse to encrypt 2 --> mask bit if data bit is 0, non-mask bit if data bit is 1
    # (data => mask) & ((~data) => (~mask))
    # (a => b) = ~a | b
    # (~data | mask) & (data | ~mask)
    mask = bytes.fromhex(hashlib.sha512(password.encode("utf-8")).hexdigest())
    return bytes((negate(val) | mask[i % len(mask)]) & (val | negate(mask[i % len(mask)])) for i, val in enumerate(data))

if __name__ == '__main__':
    main()