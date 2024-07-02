#!/usr/bin/env python3
import lzma
import os
import sys
import time
import psutil
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from Cryptodome.Cipher import AES


class STADAESEncryptionTool:
    """ "AESEncryptionTool" class from "github.com/nsk89" for file encryption.
    (Has been modified a bit.) """

    def __init__(self, user_file, user_key):
        self.report_standard_aes_result = ""
        # get the path to input file
        self.user_file = user_file

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "SHA256"

    def encrypt(self):
        # Get the file name from the entry field
        filename = self.user_file

        if filename:
            # set encryption key
            key = self.user_key

            # read in file data
            with open(filename, 'rb') as f:
                data = f.read()

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
            result = "Encryption time: {:.4f} seconds\n".format(end_time - start_time)
            result += "Memory utilization: {:.2f} MB".format(mem_usage / 1024 / 1024)
            self.report_standard_aes_result = result

            # write encrypted data to file
            enc_filename = filename + ".ecryp"
            with open(enc_filename, 'wb') as f:
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)
        else:
            self.report_standard_aes_result = "Error: No file entered."

    def decrypt(self):
        # Get the file name from the entry field
        filename = self.user_file.get()

        if filename:
            # set encryption key
            key = self.user_key

            # decrypt the data
            with open(filename, 'rb') as f:
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()

            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

            # decrypt the data
            start_time = time.time()
            data = cipher.decrypt_and_verify(ciphertext, tag)
            end_time = time.time()

            # calculate memory usage
            process = psutil.Process(os.getpid())
            mem_usage = process.memory_info().rss

            # unpad data
            unpad = lambda s: s[0:-s[-1]]
            data = unpad(data)

            # write decrypted data to file
            dec_filename = filename + ".dcryp"
            with open(dec_filename, 'wb') as f:
                f.write(data)

            # print out results
            result = "Decryption time: {:.4f} seconds\n".format(end_time - start_time)
            result += "Memory utilization: {:.2f} MB".format(mem_usage / 1024 / 1024)
            self.report_result = result
        else:
            self.report_result = "Error: No file entered."

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)


class EFFAESEncryptionTool:
    """ "AESEncryptionTool" class from "github.com/nsk89" for file encryption.
    (Has been modified a bit.) """

    def __init__(self, user_file, user_key):
        self.report_result = ""
        # get the path to input file
        self.user_file = user_file

        # convert the key and salt to bytes
        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # get the file extension
        self.file_extension = self.user_file.split(".")[-1]

        # hash type for hashing key and salt
        self.hash_type = "SHA256"


    def encrypt(self):
        # Get the file name from the entry field
        filename = self.user_file

        if filename:
            # set encryption key
            key = self.user_key

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
            result = "Encryption time: {:.4f} seconds\n".format(end_time - start_time)
            result += "Memory utilization: {:.2f} MB".format(mem_usage / 1024 / 1024)
            self.report_result = result

            # write encrypted data to file
            enc_filename = filename + ".ecryp"
            with open(enc_filename, 'wb') as f:
                f.write(cipher.nonce)
                f.write(tag)
                f.write(ciphertext)
        else:
            self.report_result = "Error: No file entered."

    def decrypt(self):
        # Get the file name from the entry field
        filename = self.user_file.get()

        if filename:
            # set encryption key
            key = self.user_key

            # decrypt the data
            with open(filename, 'rb') as f:
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()

            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

            # decrypt the data
            start_time = time.time()
            data = cipher.decrypt_and_verify(ciphertext, tag)
            end_time = time.time()

            # calculate memory usage
            process = psutil.Process(os.getpid())
            mem_usage = process.memory_info().rss

            # unpad data
            unpad = lambda s: s[0:-s[-1]]
            data = unpad(data)

            # uncompress data
            data = lzma.decompress(data)

            # write decrypted data to file
            dec_filename = filename + ".dcryp"
            with open(dec_filename, 'wb') as f:
                f.write(data)

            # print out results
            result = "Decryption time: {:.4f} seconds\n".format(end_time - start_time)
            result += "Memory utilization: {:.2f} MB".format(mem_usage / 1024 / 1024)
            self.report_result = result
        else:
            self.report_result = "Error: No file entered."

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)


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

        self.should_cancel = False

        root.title("EEF File Encryption Software")
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
        self.choose_algorithm_cb = ttk.Combobox(
            root,
            values=["EEF-AES", "STANDARD-AES"],
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
        if self.choose_algorithm_cb.get() == 'EEF-AES':
            self.eff_aes_encrypt_callback()
        if self.choose_algorithm_cb.get() == 'STANDARD-AES':
            self.stan_aes_encrypt_callback()

    def decrypt_algorithm_selector(self):
        if self.choose_algorithm_cb.get() == 'EEF-AES':
            self.eff_aes_decrypt_callback()
        if self.choose_algorithm_cb.get() == 'STANDARD-AES':
            self.stan_aes_decrypt_callback()

    # STANDARD AES ENCRYPTION AND DECRYPTION CALLBACK
    def stan_aes_encrypt_callback(self):
        self.freeze_controls()
        try:
            self._cipher = STADAESEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )
            self._cipher.encrypt()
            self._status.set("File Encrypted!")
            self._report.set(self._cipher.report_standard_aes_result)
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(e)

        self.unfreeze_controls()

    def stan_aes_decrypt_callback(self):
        self.freeze_controls()

        try:
            self._cipher = STADAESEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )
            self._cipher.decrypt()
            self._status.set("File Decrypted!")
            self._report.set(self._cipher.report_standard_aes_result)
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()

    # EEF AES ENCRYPTION AND DECRYPTION CALLBACK
    def eff_aes_encrypt_callback(self):
        self.freeze_controls()
        try:
            self._cipher = EFFAESEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )
            self._cipher.encrypt()
            self._status.set("File Encrypted!")
            self._report.set(self._cipher.report_result)
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            self._status.set(e)

        self.unfreeze_controls()

    def eff_aes_decrypt_callback(self):
        self.freeze_controls()
        try:
            self._cipher = EFFAESEncryptionTool(
                self._file_url.get(),
                self._secret_key.get(),
            )
            self._cipher.decrypt()
            self._status.set("File Decrypted!")
            self._report.set(self._cipher.report_result)
            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Cancelled!")
            self._cipher = None
            self.should_cancel = False
        except Exception as e:
            # print(e)
            self._status.set(e)

        self.unfreeze_controls()

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