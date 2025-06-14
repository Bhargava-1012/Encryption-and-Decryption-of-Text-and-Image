import tkinter as tk
from tkinter import messagebox, filedialog
import base64
import os

# Simple XOR encryption function
def xor_encrypt(text, key):
    encrypted_chars = []
    for i in range(len(text)):
        encrypted_chars.append(chr(ord(text[i]) ^ ord(key[i % len(key)])))
    encrypted_text = ''.join(encrypted_chars)
    return base64.b64encode(encrypted_text.encode('utf-8')).decode('utf-8')

# Simple XOR decryption function
def xor_decrypt(encrypted_text, key):
    decrypted_chars = []
    decoded_encrypted_text = base64.b64decode(encrypted_text).decode('utf-8')
    for i in range(len(decoded_encrypted_text)):
        decrypted_chars.append(chr(ord(decoded_encrypted_text[i]) ^ ord(key[i % len(key)])))
    return ''.join(decrypted_chars)

# Function to save text to a file
def save_to_file(folder, filename, text):
    with open(os.path.join(folder, filename), 'w') as file:
        file.write(text)

# Function to get the text and key from entries, encrypt it, show and save it
def encrypt_message():
    msg = entry.get()
    key = key_entry.get()
    if msg and key:
        encrypted_msg = xor_encrypt(msg, key)
        result_entry.delete(0, tk.END)
        result_entry.insert(0, encrypted_msg)  # Display encrypted message
        folder = filedialog.askdirectory()
        if folder:
            save_to_file(folder, 'encrypted.txt', encrypted_msg)  # Save encrypted message
            save_to_file(folder, 'key.txt', key)  # Save key separately
    else:
        messagebox.showerror("Error", "Please enter some text and a key to encrypt.")

# Function to get the encrypted text and key from entries, decrypt it, show and save it
def decrypt_message():
    encrypted_msg = entry.get()
    key = key_entry.get()
    if encrypted_msg and key:
        try:
            decrypted_msg = xor_decrypt(encrypted_msg, key)
            result_entry.delete(0, tk.END)
            result_entry.insert(0, decrypted_msg)  # Display decrypted message
            folder = filedialog.askdirectory()
            if folder:
                save_to_file(folder, 'decrypted.txt', decrypted_msg)  # Save decrypted message
        except Exception as e:
            messagebox.showerror("Error", "Invalid encryption or other error: " + str(e))
    else:
        messagebox.showerror("Error", "Please enter some encrypted text and a key to decrypt.")

# Creating main window
root = tk.Tk()
root.title("Text Encryption and Decryption with Key")

# Creating frame for input and buttons
frame = tk.Frame(root)
frame.pack(pady=20)

# Creating entry widget for message input or encrypted text input
entry_label = tk.Label(frame, text="Enter Text or Encrypted Text:")
entry_label.pack(side=tk.TOP)
entry = tk.Entry(frame, width=50)
entry.pack(side=tk.TOP, pady=10)

# Creating entry widget for key input
key_label = tk.Label(frame, text="Enter Key:")
key_label.pack(side=tk.TOP)
key_entry = tk.Entry(frame, width=50)
key_entry.pack(side=tk.TOP, pady=10)

# Creating frame for buttons
button_frame = tk.Frame(frame)
button_frame.pack(pady=10)

# Creating buttons for triggering encryption and decryption
encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_message)
encrypt_button.pack(side=tk.LEFT, padx=10)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_message)
decrypt_button.pack(side=tk.RIGHT, padx=10)

# Entry to display result which allows copying of text
result_entry = tk.Entry(root, width=50)
result_entry.pack(pady=10)

# Running the application
root.mainloop()
