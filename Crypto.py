from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA256, SHA512, SHA3_256
from Cryptodome.PublicKey import RSA, DSA
from Cryptodome.Signature import DSS
from datetime import datetime, time
from base64 import b64encode
import os

def AES_128(file_name):
    print()
    print('AES 128 for ' + file_name + ':   ')
    # ENCRYPTION
    t1 = datetime.now()
    key = get_random_bytes(16)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    initial_vector = get_random_bytes(16)
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=initial_vector, use_aesni='true')
    print('KEY:(byte) ' + str(key))
    print('INITIAL VECTOR:(byte)  ' + str(initial_vector))
    # print('PLAINTEXT AS BYTES:  ')
    # print(plaintext)
    # key_str = b64encode(key).decode('utf-8')
    # print(key_str)
    t1 = datetime.now()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    t2 = datetime.now()
    enc_speed = t2 - t1
    print('TIME TAKEN FOR ENCRYPTION:(micro seconds)    ' + str(enc_speed.microseconds))
    # print('CIPHERTEXT AS BYTES: ')
    # print(ciphertext)
    # ct = b64encode(ciphertext).decode('utf-8')
    # print(ct)
    with open(file_name + "_Encrypt_AES128.txt", "w") as text_file:
        text_file.write(str(ciphertext))
    print("THE ENCRYPTED FILE IS SAVED AS: " + file_name + "_Encrypt_AES128.txt .....SUCCESS!")
    # DECRYPTION
    try:
        plain = AES.new(key, AES.MODE_CBC, iv=initial_vector, use_aesni='true')
        t1 = datetime.now()
        pt = plain.decrypt(ciphertext)
        t2 = datetime.now()
        dec_speed = t2 - t1
        print('TIME TAKEN FOR DECRYPTION:(micro seconds)    ' + str(dec_speed.microseconds))
        plaintext_decrypt = unpad(pt, AES.block_size).decode('utf-8')
        # print(plaintext_decrypt)
        with open(file_name + "_Decrypt_AES128.txt", "w") as text_file:
            text_file.write(plaintext_decrypt)
        print("THE DECRYPTED FILE IS SAVED AS: " + file_name + "_Decrypt_AES128.txt .....SUCCESS!")
    except (ValueError, KeyError):
        print("INCORRECT DECRYPTION!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    enc_byte = enc_speed.microseconds / size
    dec_byte = dec_speed.microseconds / size
    print("ENCRYPTION SPEED PER BYTE:   " + str(enc_byte))
    print("DECRYPTION SPEED PER BYTE:   " + str(dec_byte))

def CTR_128(file_name):
    print()
    print('CTR 128 for ' + file_name + ':   ')
    # ENCRYPTION
    t1 = datetime.now()
    key = get_random_bytes(16)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    #initial_vector = get_random_bytes(16)
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_CTR, use_aesni='true')
    nonce = cipher.nonce
    print('KEY:(byte) ' + str(key))
    print('NONCE:  ' + str(nonce))
    # print('PLAINTEXT AS BYTES:  ')
    # print(plaintext)
    # key_str = b64encode(key).decode('utf-8')
    # print(key_str)
    t1 = datetime.now()
    ciphertext = cipher.encrypt(plaintext)
    t2 = datetime.now()
    enc_speed = t2 - t1
    print('TIME TAKEN FOR ENCRYPTION:(micro seconds)    ' + str(enc_speed.microseconds))
    # print('CIPHERTEXT AS BYTES: ')
    # print(ciphertext)
    # ct = b64encode(ciphertext).decode('utf-8')
    # print(ct)
    with open(file_name + "_Encrypt_CTR128.txt", "w") as text_file:
        text_file.write(str(ciphertext))
    print("THE ENCRYPTED FILE IS SAVED AS: " + file_name + "_Encrypt_CTR128.txt .....SUCCESS!")
    # DECRYPTION
    try:
        plain = AES.new(key, AES.MODE_CTR, nonce=nonce, use_aesni='true')
        t1 = datetime.now()
        pt = plain.decrypt(ciphertext)
        t2 = datetime.now()
        dec_speed = t2 - t1
        print('TIME TAKEN FOR DECRYPTION:(micro seconds)    ' + str(dec_speed.microseconds))
        plaintext_decrypt = pt.decode('utf-8')
        # print(plaintext_decrypt)
        with open(file_name + "_Decrypt_CTR128.txt", "w") as text_file:
            text_file.write(plaintext_decrypt)
        print("THE DECRYPTED FILE IS SAVED AS: " + file_name + "_Decrypt_CTR128.txt .....SUCCESS!")
    except (ValueError, KeyError):
        print("INCORRECT DECRYPTION!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    enc_byte = enc_speed.microseconds / size
    dec_byte = dec_speed.microseconds / size
    print("ENCRYPTION SPEED PER BYTE:      " + str(enc_byte))
    print("DECRYPTION SPEED PER BYTE:      " + str(dec_byte))

def CTR_256(file_name):
    print()
    print('CTR 256 for ' + file_name + ':   ')
    # ENCRYPTION
    t1 = datetime.now()
    key = get_random_bytes(32)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    #initial_vector = get_random_bytes(16)
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_CTR, use_aesni='true')
    nonce = cipher.nonce
    print('KEY:(byte) ' + str(key))
    print('NONCE:  ' + str(nonce))
    # print('PLAINTEXT AS BYTES:  ')
    # print(plaintext)
    # key_str = b64encode(key).decode('utf-8')
    # print(key_str)
    t1 = datetime.now()
    ciphertext = cipher.encrypt(plaintext)
    t2 = datetime.now()
    enc_speed = t2 - t1
    print('TIME TAKEN FOR ENCRYPTION:(micro seconds)    ' + str(enc_speed.microseconds))
    # print('CIPHERTEXT AS BYTES: ')
    # print(ciphertext)
    # ct = b64encode(ciphertext).decode('utf-8')
    # print(ct)
    with open(file_name + "_Encrypt_CTR256.txt", "w") as text_file:
        text_file.write(str(ciphertext))
    print("THE ENCRYPTED FILE IS SAVED AS: "    + file_name + "_Encrypt_CTR256.txt .....SUCCESS!")
    # DECRYPTION
    try:
        plain = AES.new(key, AES.MODE_CTR, nonce=nonce, use_aesni='true')
        t1 = datetime.now()
        pt = plain.decrypt(ciphertext)
        t2 = datetime.now()
        dec_speed = t2 - t1
        print('TIME TAKEN FOR DECRYPTION:(micro seconds)    ' + str(dec_speed.microseconds))
        plaintext_decrypt = pt.decode('utf-8')
        # print(plaintext_decrypt)
        with open(file_name + "_Decrypt_CTR256.txt", "w") as text_file:
            text_file.write(plaintext_decrypt)
        print("THE DECRYPTED FILE IS SAVED AS: "    + file_name + "_Decrypt_CTR256.txt .....SUCCESS!")
    except (ValueError, KeyError):
        print("INCORRECT DECRYPTION!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    enc_byte = enc_speed.microseconds / size
    dec_byte = dec_speed.microseconds / size
    print("ENCRYPTION SPEED PER BYTE:   " + str(enc_byte))
    print("DECRYPTION SPEED PER BYTE:   " + str(dec_byte))

def SHA_256(file_name):
    print()
    print('SHA-256:- The hash value for ' + file_name + ' is:   ')
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    hash_gen = SHA256.new()
    t1 = datetime.now()
    hash_gen.update(plaintext)
    t2 = datetime.now()
    hash_time = t2 -t1
    print('TIME TAKEN FOR HASHING:(micro seconds)    ' + str(hash_time.microseconds))
    print (hash_gen.hexdigest())
    with open(file_name + "_SHA256.txt", "w") as text_file:
        text_file.write(hash_gen.hexdigest())
    print("THE HASH FILE IS SAVED AS: "    + file_name + "_SHA256.txt .....SUCCESS!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    hash_byte = hash_time.microseconds / size
    print("HASH SPEED PER BYTE:   " + str(hash_byte))

def SHA_512(file_name):
    print()
    print('SHA-512:- The hash value for ' + file_name + ' is:   ')
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    hash_gen = SHA512.new()
    t1 = datetime.now()
    hash_gen.update(plaintext)
    t2 = datetime.now()
    hash_time = t2 - t1
    print('TIME TAKEN FOR HASHING:(micro seconds)    ' + str(hash_time.microseconds))
    print (hash_gen.hexdigest())
    with open(file_name + "_SHA512.txt", "w") as text_file:
        text_file.write(hash_gen.hexdigest())
    print("THE HASH FILE IS SAVED AS: "    + file_name + "_SHA512.txt .....SUCCESS!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    hash_byte = hash_time.microseconds / size
    print("HASH SPEED PER BYTE:   " + str(hash_byte))

def SHA3__256(file_name):
    print()
    print('SHA3-256:- The hash value for ' + file_name + ' is:   ')
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    hash_gen = SHA3_256.new()
    t1 = datetime.now()
    hash_gen.update(plaintext)
    t2 = datetime.now()
    hash_time = t2 -t1
    print (hash_gen.hexdigest())
    print('TIME TAKEN FOR HASHING:(micro seconds)    ' + str(hash_time.microseconds))
    with open(file_name + "_SHA3-256.txt", "w") as text_file:
        text_file.write(hash_gen.hexdigest())
    print("THE HASH FILE IS SAVED AS: "    + file_name + "_SHA2-256.txt .....SUCCESS!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    print(size)
    hash_byte = hash_time.microseconds / size
    print("HASH SPEED PER BYTE:   " + str(hash_byte))

def RSA_2048(file_name):
    print()
    print('RSA 2048 for ' + file_name + ':   ')
    #KEY GENERATION
    t1 = datetime.now()
    key_gen = RSA.generate(2048)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    f = open('RSA2048_CSE565.pem', 'wb')
    f.write(key_gen.export_key('PEM'))
    f.close()
    #ENCRYPTION
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    f = open('RSA2048_CSE565.pem', 'r')
    key = RSA.import_key(f.read())
    # public_key = key.publickey()
    cipher = PKCS1_OAEP.new(key)
    t1 = datetime.now()
    ciphertext = cipher.encrypt(plaintext)
    t2 = datetime.now()
    enc_speed = t2 - t1
    print('TIME TAKEN FOR ENCRYPTION:(micro seconds)    ' + str(enc_speed.microseconds))
    with open(file_name + "_Encrypt_RSA2048.txt", "w") as text_file:
        text_file.write(str(ciphertext))
    print("THE ENCRYPTED FILE IS SAVED AS: "    + file_name + "_Encrypt_RSA2048.....SUCCESS!")
    #DECRYPTION
    try:
        # private_key = key.has_private()
        plain = PKCS1_OAEP.new(key)
        t1 = datetime.now()
        pt = plain.decrypt(ciphertext)
        t2 = datetime.now()
        dec_speed = t2 - t1
        print('TIME TAKEN FOR DECRYPTION:(micro seconds)    ' + str(dec_speed.microseconds))
        plaintext_decrypt = pt.decode('utf-8')
        # print(plaintext_decrypt)
        with open(file_name + "_Decrypt_RSA2048.txt", "w") as text_file:
            text_file.write(plaintext_decrypt)
        print("THE DECRYPTED FILE IS SAVED AS: "    + file_name + "_Decrypt_RSA2048.....SUCCESS!")
    except (ValueError, KeyError):
        print("INCORRECT DECRYPTION!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    enc_byte = enc_speed.microseconds / size
    dec_byte = dec_speed.microseconds / size
    print("ENCRYPTION SPEED PER BYTE:   " + str(enc_byte))
    print("DECRYPTION SPEED PER BYTE:   " + str(dec_byte))

def RSA_3072(file_name):
    print()
    print('RSA 3072 for ' + file_name + ':   ')
    #KEY GENERATION
    t1 = datetime.now()
    key_gen = RSA.generate(3072)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    f = open('RSA3072_CSE565.pem', 'wb')
    f.write(key_gen.export_key('PEM'))
    f.close()
    #ENCRYPTION
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    f = open('RSA3072_CSE565.pem', 'r')
    key = RSA.import_key(f.read())
    # public_key = key.publickey()
    cipher = PKCS1_OAEP.new(key)
    t1 = datetime.now()
    ciphertext = cipher.encrypt(plaintext)
    t2 = datetime.now()
    enc_speed = t2 - t1
    print('TIME TAKEN FOR ENCRYPTION:(micro seconds)    ' + str(enc_speed.microseconds))
    with open(file_name + "_Encrypt_RSA3072.txt", "w") as text_file:
        text_file.write(str(ciphertext))
    print("THE ENCRYPTED FILE IS SAVED AS: "    + file_name + "_Encrypt_RSA3072.....SUCCESS!")
    #DECRYPTION
    try:
        # private_key = key.has_private()
        plain = PKCS1_OAEP.new(key)
        t1 = datetime.now()
        pt = plain.decrypt(ciphertext)
        t2 = datetime.now()
        dec_speed = t2 - t1
        print('TIME TAKEN FOR DECRYPTION:(micro seconds)    ' + str(dec_speed.microseconds))
        plaintext_decrypt = pt.decode('utf-8')
        # print(plaintext_decrypt)
        with open(file_name + "_Decrypt_RSA3072.txt", "w") as text_file:
            text_file.write(plaintext_decrypt)
        print("THE DECRYPTED FILE IS SAVED AS: "    + file_name + "_Decrypt_RSA3072.....SUCCESS!")
    except (ValueError, KeyError):
        print("INCORRECT DECRYPTION!")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    enc_byte = enc_speed.microseconds / size
    dec_byte = dec_speed.microseconds / size
    print("ENCRYPTION SPEED PER BYTE:   " + str(enc_byte))
    print("DECRYPTION SPEED PER BYTE:   " + str(dec_byte))

def DSA_2048(file_name):
    print()
    print('DSA 2048 for ' + file_name + ':   ')
    #KEY GENERATION
    t1 = datetime.now()
    key = DSA.generate(2048)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    f = open("DSA2048_CSE565.pem", "wb")
    f.write(key.publickey().export_key())
    f.close()
    #SIGNING
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    hash_gen = SHA256.new(plaintext)
    signer = DSS.new(key, 'fips-186-3')
    t1 = datetime.now()
    signature = signer.sign(hash_gen)
    t2 = datetime.now()
    sign_time = t2 - t1
    print('TIME TAKEN TO SIGN:(micro seconds)    ' + str(sign_time.microseconds))
    #VERIFIER
    f = open("DSA2048_CSE565.pem", "r")
    hash_gen = SHA256.new(plaintext)
    public_key = DSA.import_key(f.read())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        t1 = datetime.now()
        verifier.verify(hash_gen, signature)
        t2 = datetime.now()
        verify_time = t2 - t1
        print('TIME TAKEN TO VERIFY:(micro seconds)    ' + str(verify_time.microseconds))
        print("THE SIGNATURE MATCHES!   The message is authentic")
    except ValueError:
        print("The message is not authentic.")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    sign_byte = sign_time.microseconds / size
    verify_byte = verify_time.microseconds / size
    print("TIME TO SIGN PER BYTE:   " + str(sign_byte))
    print("TIME TO VERIFY PER BYTE:   " + str(verify_byte))

def DSA_3072(file_name):
    print()
    print('DSA 3072 for ' + file_name + ':   ')
    #KEY GENERATION
    t1 = datetime.now()
    key = DSA.generate(3072)
    t2 = datetime.now()
    key_speed = t2 - t1
    print('TIME TAKEN FOR KEY GENERATION:(micro seconds)    ' + str(key_speed.microseconds))
    f = open("DSA3072_CSE565.pem", "wb")
    f.write(key.publickey().export_key())
    f.close()
    #SIGNING
    with open (file_name + ".txt", "r") as myfile:
        data=myfile.read()
    plaintext = bytes(data, 'utf-8')
    hash_gen = SHA256.new(plaintext)
    signer = DSS.new(key, 'fips-186-3')
    t1 = datetime.now()
    signature = signer.sign(hash_gen)
    t2 = datetime.now()
    sign_time = t2 - t1
    print('TIME TAKEN TO SIGN:(micro seconds)    ' + str(sign_time.microseconds))
    #VERIFIER
    f = open("DSA3072_CSE565.pem", "r")
    hash_gen = SHA256.new(plaintext)
    public_key = DSA.import_key(f.read())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        t1 = datetime.now()
        verifier.verify(hash_gen, signature)
        t2 = datetime.now()
        verify_time = t2 - t1
        print('TIME TAKEN TO VERIFY:(micro seconds)    ' + str(verify_time.microseconds))
        print("THE SIGNATURE MATCHES!   The message is authentic")
    except ValueError:
        print("The message is not authentic.")
    statinfo = os.stat(file_name + ".txt")
    size = statinfo.st_size
    sign_byte = sign_time.microseconds / size
    verify_byte = verify_time.microseconds / size
    print("TIME TO SIGN PER BYTE:   " + str(sign_byte))
    print("TIME TO VERIFY PER BYTE:   " + str(verify_byte))


if __name__ == "__main__":
    AES_128('INPUT_SMALL')
    AES_128('INPUT_BIG')
    CTR_128('INPUT_SMALL')
    CTR_128('INPUT_BIG')
    CTR_256('INPUT_SMALL')
    CTR_256('INPUT_BIG')
    SHA_256('INPUT_SMALL')
    SHA_256('INPUT_BIG')
    SHA_512('INPUT_SMALL')
    SHA_512('INPUT_BIG')
    SHA3__256('INPUT_SMALL')
    SHA3__256('INPUT_BIG')
    DSA_2048('INPUT_SMALL')
    DSA_2048('INPUT_BIG')
    DSA_3072('INPUT_SMALL')
    DSA_3072('INPUT_BIG')