import os
import time
import psutil
from Cryptodome.Cipher import AES
import lzma

# get user input for file name
filename = input("Enter the name of the file to encrypt: ")

# set encryption key
key = b'example_key_1234'

# read in file data
with open(filename, 'rb') as f:
    data = f.read()

# shrink data using lzma compression
data = lzma.compress(data)

# pad data to fit AES block size
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * bytes([BS - len(s) % BS])
data = pad(data)

# create AES cipher object
cipher = AES.new(key, AES.MODE_EAX)

# encrypt the data
start_time = time.time()
ciphertext, tag = cipher.encrypt_and_digest(data)
end_time = time.time()

# calculate memory usage
process = psutil.Process(os.getpid())
mem_usage = process.memory_info().rss

# print out results
print("Encryption time: {:.4f} seconds".format(end_time - start_time))
print("Memory utilization: {:.2f} MB".format(mem_usage / 1024 / 1024))

# write encrypted data to file
enc_filename = filename + ".enc"
with open(enc_filename, 'wb') as f:
    f.write(cipher.nonce)
    f.write(tag)
    f.write(ciphertext)

# decrypt the data
with open(enc_filename, 'rb') as f:
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read()

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
start_time = time.time()
data = cipher.decrypt_and_verify(ciphertext, tag)
end_time = time.time()

# calculate memory usage
process = psutil.Process(os.getpid())
mem_usage = process.memory_info().rss

# unpad data
unpad = lambda s : s[0:-s[-1]]
data = unpad(data)

# uncompress data
data = lzma.decompress(data)

# write decrypted data to file
dec_filename = filename + ".dec"
with open(dec_filename, 'wb') as f:
    f.write(data)

# print out results
print("Decryption time: {:.4f} seconds".format(end_time - start_time))
print("Memory utilization: {:.2f} MB".format(mem_usage / 1024 / 1024))
