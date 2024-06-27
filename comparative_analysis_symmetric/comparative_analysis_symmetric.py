#!/usr/bin/env python3
"""
    Name: KAEncrypt
    Type: File Encryption GUI App
    Credits: "EncryptionTool" class from "github.com/nsk89" for file encryption
"""

import os
import sys
import hashlib
import time
import tkinter as tk
import tracemalloc
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import Blowfish
from Cryptodome.Cipher import DES3
#from twofish import Twofish
from CryptoPlus.Cipher import python_Twofish
from CryptoPlus.Cipher import python_Serpent


# import threading


class AESEncryptionTool:
    """ "AESEncryptionTool" class from "github.com/nsk89" for file encryption.
    (Has been modified a bit.) """

    def __init__(self, user_file, user_key, user_salt):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "SHA256"

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
                                   + "." + self.file_extension + ".kryp"

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
                                   + "__dekrypted__." + self.decrypt_output_file[-1]

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Code Courtesy: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CFB,
            self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decrypt(self):
        #  exact same as above function except in reverse
        cipher_object = AES.new(
            self.hashed_key_salt["key"],
            AES.MODE_CFB,
            self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):
        # --- convert key to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 16 bytes (128 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher

        # --- convert salt to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 16 bytes (128 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher


class BlowfishEncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "MD5"

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
                                   + "." + self.file_extension + ".kryp"

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
                                   + "__dekrypted__." + self.decrypt_output_file[-1]

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Code Courtesy: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = Blowfish.new(
            self.hashed_key_salt["key"],
            Blowfish.MODE_CFB,
            self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decrypt(self):
        #  exact same as above function except in reverse
        cipher_object = Blowfish.new(
            self.hashed_key_salt["key"],
            Blowfish.MODE_CFB,
            self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):
        # --- convert key to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 16 bytes (128 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:8], "utf-8")

        # clean up hash object
        del hasher

        # --- convert salt to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 8 bytes (64 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:8], "utf-8")

        # clean up hash object
        del hasher


class TwofishEncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
        # get the path to input file
        self.user_file = user_file
        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 128
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "MD5"

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
                                   + "." + self.file_extension + ".kryp"

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
                                   + "__dekrypted__." + self.decrypt_output_file[-1]

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=128):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Code Courtesy: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = python_Twofish.new(
            self.hashed_key_salt["key"],
            python_Twofish.MODE_CFB,
            self.hashed_key_salt["salt"],
            self.total_chunks,
            self.chunk_size
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decrypt(self):
        #  exact same as above function except in reverse
        cipher_object = python_Twofish.new(
            self.hashed_key_salt["key"],
            python_Twofish.MODE_CFB,
            self.hashed_key_salt["salt"],
            self.total_chunks,
            self.chunk_size
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):
        # --- convert key to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 16 bytes (128 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher

        # --- convert salt to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 16 bytes (128 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher


class DES3EncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "MD5"

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
                                   + "." + self.file_extension + ".kryp"

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
                                   + "__dekrypted__." + self.decrypt_output_file[-1]

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Code Courtesy: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = DES3.new(
            self.hashed_key_salt["key"],
            DES3.MODE_CFB,
            self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decrypt(self):
        #  exact same as above function except in reverse
        cipher_object = DES3.new(
            self.hashed_key_salt["key"],
            DES3.MODE_CFB,
            self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):
        # --- convert key to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 16 bytes (128 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher

        # --- convert salt to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 8 bytes (64 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:8], "utf-8")

        # clean up hash object
        del hasher


class SerpentEncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
        # get the path to input file
        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 128
        self.total_chunks = (self.input_file_size // self.chunk_size) + 1

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "MD5"

        # encrypted file name
        self.encrypt_output_file = ".".join(self.user_file.split(".")[:-1]) \
                                   + "." + self.file_extension + ".kryp"

        # decrypted file name
        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = ".".join(self.decrypt_output_file[:-1]) \
                                   + "__dekrypted__." + self.decrypt_output_file[-1]

        # dictionary to store hashed key and salt
        self.hashed_key_salt = dict()

        # hash key and salt into 16 bit hashes
        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=128):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k.
        Code Courtesy: https://stackoverflow.com/questions/519633/lazy-method-for-reading-big-file-in-python
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = python_Serpent.new(
            self.hashed_key_salt["key"],
            python_Serpent.MODE_CFB,
            self.hashed_key_salt["salt"],
            self.total_chunks,
            self.chunk_size
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decrypt(self):
        #  exact same as above function except in reverse
        cipher_object = python_Serpent.new(
            self.hashed_key_salt["key"],
            python_Serpent.MODE_CFB,
            self.hashed_key_salt["salt"],
            self.total_chunks,
            self.chunk_size
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield (done_chunks / self.total_chunks) * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):
        # --- convert key to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 16 bytes (128 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher

        # --- convert salt to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 16 bytes (128 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher
# class EncryptionThread(threading.Thread):
#     mutual_space = {}
#     threadLock = threading.Lock()

#     def __init__(self, index):
#         threading.Thread.__init__(self)
#         self.threadID = index

#     def run(self):
#         try:
#             pass
#         except Exception as e:
#             print(e)
#             return

#         # Get lock to synchronize threads
#         self.threadLock.acquire()
#         # Append stuff to mutual_space

#         # Free lock to release next thread
#         self.threadLock.release()


class MainWindow:
    """ GUI Wrapper """
    # configure root directory path relative to this file
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        # frozen
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        # unfrozen
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._salt = tk.StringVar()
        self._status = tk.StringVar()
        self._status.set("---")
        self._report = tk.StringVar()
        self._report.set("---")
        # self._memory_utilization.set("---")
        # self._power_consumption.set("---")

        self.should_cancel = False

        root.title("KAEncrypt | Encryption Simulator")
        root.configure(bg="#eeeeee")

        try:
            icon_img = tk.Image(
                "photo",
                file=self.THIS_FOLDER_G + "/assets/app_icon.png"
            )
            root.call(
                "wm",
                "iconphoto",
                root._w,
                icon_img
            )
        except Exception:
            pass

        self.menu_bar = tk.Menu(
            root,
            bg="#eeeeee",
            relief=tk.FLAT
        )
        self.menu_bar.add_command(
            label="How To",
            command=self.show_help_callback
        )
        self.menu_bar.add_command(
            label="Quit!",
            command=root.quit
        )

        root.configure(
            menu=self.menu_bar
        )

        self.file_entry_label = tk.Label(
            root,
            text="Enter File Path Or Click SELECT FILE Button",
            bg="#eeeeee",
            anchor=tk.W
        )
        self.file_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.file_entry = tk.Entry(
            root,
            textvariable=self._file_url,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.file_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.select_btn = tk.Button(
            root,
            text="SELECT FILE",
            command=self.selectfile_callback,
            width=42,
            bg="#1089ff",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.select_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )
        selected_algorithm = tk.StringVar()
        self.choose_algorithm_cb = ttk.Combobox(
            root,
            values=["AES", "Blowfish", "Twofish", "DES3", "Serpent"],
            state="readonly"
        )
        self.choose_algorithm_cb.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.key_entry_label = tk.Label(
            root,
            text="Enter Secret Key (Remember this for Decryption)",
            bg="#eeeeee",
            anchor=tk.W
        )
        self.key_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.key_entry = tk.Entry(
            root,
            textvariable=self._secret_key,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT
        )
        self.key_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.encrypt_btn = tk.Button(
            root,
            text="ENCRYPT",
            command=self.encrypt_algorithm_selector,
            bg="#ed3833",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.encrypt_btn.grid(
            padx=(15, 6),
            pady=8,
            ipadx=24,
            ipady=6,
            row=8,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.decrypt_btn = tk.Button(
            root,
            text="DECRYPT",
            command=self.decrypt_algorithm_selector,
            bg="#00bd56",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.decrypt_btn.grid(
            padx=(6, 15),
            pady=8,
            ipadx=24,
            ipady=6,
            row=8,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.reset_btn = tk.Button(
            root,
            text="RESET",
            command=self.reset_callback,
            bg="#aaaaaa",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT
        )
        self.reset_btn.grid(
            padx=15,
            pady=(4, 12),
            ipadx=24,
            ipady=6,
            row=10,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.status_label = tk.Label(
            root,
            textvariable=self._status,
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350
        )
        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=12,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        self.time_label = tk.Label(
            root,
            textvariable=self._report,
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350
        )
        self.time_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=13,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S
        )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)
        self.choose_algorithm_cb.set("Choose Data Encryption Algorithms")

    def selectfile_callback(self):
        try:
            name = filedialog.askopenfile()
            self._file_url.set(name.name)
            # print(name.name)
        except Exception as e:
            self._status.set(e)
            self.status_label.update()

    def freeze_controls(self):
        self.file_entry.configure(state="disabled")
        self.key_entry.configure(state="disabled")
        self.select_btn.configure(state="disabled")
        self.encrypt_btn.configure(state="disabled")
        self.decrypt_btn.configure(state="disabled")
        self.reset_btn.configure(text="CANCEL", command=self.cancel_callback,
                                 fg="#ed3833", bg="#fafafa")
        self.status_label.update()

    def unfreeze_controls(self):
        self.file_entry.configure(state="normal")
        self.key_entry.configure(state="normal")
        self.select_btn.configure(state="normal")
        self.encrypt_btn.configure(state="normal")
        self.decrypt_btn.configure(state="normal")
        self.reset_btn.configure(text="RESET", command=self.reset_callback,
                                 fg="#ffffff", bg="#aaaaaa")
        self.status_label.update()

    def encrypt_algorithm_selector(self):
        if self.choose_algorithm_cb.get() == 'AES':
            self.aes_encrypt_callback()
        if self.choose_algorithm_cb.get() == 'Blowfish':
            self.blowfish_encrypt_callback()
        if self.choose_algorithm_cb.get() == 'Twofish':
            self.twofish_encrypt_callback()
        if self.choose_algorithm_cb.get() == 'DES3':
            self.des3_encrypt_callback()
        if self.choose_algorithm_cb.get() == 'Serpent':
            self.serpent_encrypt_callback()

    def decrypt_algorithm_selector(self):
        if self.choose_algorithm_cb.get() == 'AES':
            self.aes_decrypt_callback()
        if self.choose_algorithm_cb.get() == 'Blowfish':
            self.blowfish_decrypt_callback()
        if self.choose_algorithm_cb.get() == 'Twofish':
            self.twofish_decrypt_callback()
        if self.choose_algorithm_cb.get() == 'DES3':
            self.des3_decrypt_callback()
        if self.choose_algorithm_cb.get() == 'Serpent':
            self.serpent_decrypt_callback()

    # AES ENCRYPTION AND DECRYPTION CALLBACK
    def aes_encrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = AESEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    def aes_decrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = AESEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    # BLOWFISH ENCRYPTION AND DECRYPTION CALLBACK
    def blowfish_encrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = BlowfishEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    def blowfish_decrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = BlowfishEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    # Twofish Encryption and Decryption callback
    def twofish_encrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = TwofishEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    def twofish_decrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = TwofishEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    # DES3 ENCRYPTION AND DECRYPTION CALLBACK
    def des3_encrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = DES3EncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                            + " MemUti = " + str(tracemalloc.get_traced_memory())
                            + " PowCon = 0.00")
        tracemalloc.stop()

    def des3_decrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = DES3EncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                            + " MemUti = " + str(tracemalloc.get_traced_memory())
                            + " PowCon = 0.00")
        tracemalloc.stop()

    # SERPENT ENCRYPTION AND DECRYPTION CALLBACK
    def serpent_encrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = SerpentEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Encrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    def serpent_decrypt_callback(self):
        self.freeze_controls()
        encrypt_start_time = time.time()
        tracemalloc.start()

        try:
            self._cipher = SerpentEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
                self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()
            self._status.set("File Decrypted!")
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()
        encrypt_end_time = time.time()
        elapsed_time = encrypt_end_time - encrypt_start_time
        self._report.set("TimeUti = " + str(elapsed_time) + " seconds" + " | "
                         + " MemUti = " + str(tracemalloc.get_traced_memory())
                         + " PowCon = 0.00")
        tracemalloc.stop()

    def reset_callback(self):
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._salt.set("")
        self._status.set("---")
        self._report.set("---")
        self.choose_algorithm_cb.set("Choose Data Encryption Algorithms")

    def cancel_callback(self):
        self.should_cancel = True

    def show_help_callback(self):
        messagebox.showinfo(
            "How To",
            """1. Open the App and Click SELECT FILE Button and select your file e.g. "abc.jpg".
2. Enter your Secret Key (This can be any alphanumeric letters). Remember this so you can Decrypt the file later.
3. Click ENCRYPT Button to encrypt. A new encrypted file with ".kryp" extention e.g. "abc.jpg.kryp" will be created in the same directory where the "abc.jpg" is.
4. When you want to Decrypt a file you, will select the file with the ".kryp" extention and Enter your Secret Key which you chose at the time of Encryption. Click DECRYPT Button to decrypt. The decrypted file will be of the same name as before with the suffix "__dekrypted__" e.g. "abc__dekrypted__.jpg".
5. Click RESET Button to reset the input fields and status bar.
6. You can also Click CANCEL Button during Encryption/Decryption to stop the process."""
        )


if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    ROOT.mainloop()