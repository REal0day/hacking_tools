#!/usr/bin/env python3
# crypter.py
import base64
'''
    1. encode msg
    2. encode key
    3. base64 encoded msg
    4. base64 encoded key
    5. xor
    6. b64decode msg
    7. decode msg

    Resources
    https://nitratine.net/blog/post/xor-python-byte-strings/
    https://github.com/PushpenderIndia/crypter/blob/master/Base64_encode.py
    https://0x00sec.org/t/programming-for-wanabes-xiii-crypters-part-i/27598#main-container

'''
def xsor(msg, key):
    keyIndex = 0
    xorString = ''
    for char in msg:

        keyChar = key[keyIndex]
        xorString += chr(ord(char) ^ ord(keyChar))
        keyIndex += 1
        keyIndex = keyIndex % len(key)

    return xorString
    
def xor(msg, key):
    encodedMsg = msg.encode()
    encodedKey = key.encode()
    b64EncodedMsg = base64.b64encode(encodedMsg)
    b64EncodedKey = base64.b64encode(encodedKey)

    xor = b64EncodedMsg ^ b64EncodedKey
    print(f"xor: {xor}")
    return

msg = 'this is the message string'
key = 'Secret!1'

xorString = xsor(msg, key)
print(f"xorString: {xorString}")
originalMsg = xsor(xorString, key)
print(f"originalMsg: {originalMsg}")