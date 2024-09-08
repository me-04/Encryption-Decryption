import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

def encrypt_file(input_file,output_file,key):
    fernet=Fernet(key)
    with open(input_file,"rb") as f:
        plaintext=f.read()
    ciphertext=fernet.encrypt(plaintext)
    with open(output_file,"wb") as f:
        f.write(ciphertext)

def decrypt_file(input_file,output_file,key):
    fernet=Fernet(key)
    with open(input_file,"rb") as f:
        ciphertext=f.read()
    plaintext=fernet.decrypt(ciphertext)
    with open(output_file,"wb") as f:
        f.write(plaintext)

def generate_key():
    key=Fernet.generate_key()
    return key.decode()

def show_message(msg):
    messagebox.showinfo("Info",msg)

def browse_file(entry):
    filename=filedialog.askopenfilename()
    entry.delete(0,tk.END)
    entry.insert(0,filename)

def on_generate_key(key_entry):
    key=generate_key()
    key_entry.delete(0,tk.END)
    key_entry.insert(0,key)

def on_encrypt_decrypt(action,input_file_entry,output_file_entry,key_entry):
    input_file=input_file_entry.get()
    output_file=output_file_entry.get()
    key=key_entry.get().encode()

    if not os.path.isfile(input_file):
        show_message("Input file does not exist")
        return
    
    if action == "Encrypt":
        try:
            encrypt_file(input_file,output_file,key)
            show_message(f"File Encrypted: {input_file} -> {output_file}")
        except Exception as e:
            show_message(f"Encryption failed: {str(e)}")
    elif action == "Decrypt":
        try:
            decrypt_file(input_file,output_file,key)
            show_message(f"File Decrypted: {input_file} -> {output_file}")
        except Exception as e:
            show_message(f"Decryption failed: {str(e)}")


def main():
    window = tk.Tk()
    window.title("File Encryption/Decryption Tool")

    action_label = tk.Label(window, text="Action")
    action_label.pack()

    action_var=tk.StringVar()
    action_var.set("Encrypt")
    action_radio_encrypt=tk.Radiobutton(window,text="Encrypt",variable=action_var,value="Encrypt")
    action_radio_encrypt.pack()
    action_radio_decrypt=tk.Radiobutton(window,text="Decrypt",variable=action_var,value="Decrypt")
    action_radio_decrypt.pack()

    input_file_label=tk.Label(window,text="Input File")
    input_file_label.pack()
    input_file_entry=tk.Entry(window)
    input_file_entry.pack()
    input_file_button=tk.Button(window,text="BROWSE",command=lambda:browse_file(input_file_entry))
    input_file_button.pack()

    output_file_label=tk.Label(window,text="Output File")
    output_file_label.pack()
    output_file_entry=tk.Entry(window)
    output_file_entry.pack()
    output_file_button=tk.Button(window,text="BROWSE",command=lambda:browse_file(output_file_entry))
    output_file_button.pack()

    key_label=tk.Label(window,text="Key")
    key_label.pack()
    key_entry=tk.Entry(window)
    key_entry.pack()
    generate_key_button=tk.Button(window,text="GENERATE KEY",command=lambda:on_generate_key(key_entry))
    generate_key_button.pack()

    encrypt_decrypt_button=tk.Button(window,text="ENCRYPT/DECRYPT",command=lambda:on_encrypt_decrypt(action_var.get(),input_file_entry,output_file_entry,key_entry))
    encrypt_decrypt_button.pack()

    window.mainloop()

if __name__=="__main__":
    main()