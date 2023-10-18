from hashlib import md5
from base64 import b64decode
from base64 import b64encode
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = b"1234567812345678"
iv = b"12345678ABCDEFGH"

def encrypt(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'),AES.block_size))
    return b64encode(ciphertext).decode('utf-8')

def decrypt(data):
    raw = b64decode(data)
    cipher = AES.new(key, AES.MODE_CBC,iv)
    decrypted_data = unpad(cipher.decrypt(raw), AES.block_size)
    return decrypted_data.decode('utf-8')

print('TESTING ENCRYPTION')
Input_Message = input('Message...: ')
print('Ciphertext:', encrypt(Input_Message))

print('\nTESTING DECRYPTION')
Cipher_Text = input('Ciphertext: ')
print(decrypt(Cipher_Text)
