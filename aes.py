#pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def E(P, K, iv):
    key_bytes = bytes.fromhex(K)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(P, AES.block_size))
    return cipher.iv, ciphertext

def D(iv, C, K):
    key_bytes = bytes.fromhex(K)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(C), AES.block_size)
    return decrypted

K = '2475A2B33475568831E2120013AA5487'
P = bytes.fromhex('00041214120412000C00131108231919') 
iv = bytes.fromhex('00000000000000000000000000000000') 

iv, C = E(P, K, iv)
print(f"Encrypted P: {C[:16].hex().upper()}")

decrypted_text = D(iv, C, K)
print(f"Decrypted C: {decrypted_text.hex()}") 

assert decrypted_text == P, "복호화된 평문이 원본과 일치하지 않습니다."
print("암호화 및 복호화가 완료되었습니다.\n")



K = '2475A2B33475568831E2120013AA54872475A2B334755688' 
P = bytes.fromhex('00041214120412000C00131108231919')  
iv = bytes.fromhex('00000000000000000000000000000000') 

iv, C = E(P, K, iv)
print(f"Encrypted P: {C[:16].hex().upper()}")

decrypted_text = D(iv, C, K)
print(f"Decrypted C: {decrypted_text.hex()}") 

assert decrypted_text == P, "복호화된 평문이 원본과 일치하지 않습니다."
print("암호화 및 복호화가 완료되었습니다.\n")



K = '2475A2B33475568831E2120013AA54872475A2B33475568831E2120013AA5487'  
P = bytes.fromhex('00041214120412000C00131108231919')
iv = bytes.fromhex('00000000000000000000000000000000') 

iv, C = E(P, K, iv)
print(f"Encrypted P: {C[:16].hex().upper()}")

decrypted_text = D(iv, C, K)
print(f"Decrypted C: {decrypted_text.hex()}") 

assert decrypted_text == P, "복호화된 평문이 원본과 일치하지 않습니다."
print("암호화 및 복호화가 완료되었습니다.\n")