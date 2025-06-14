import tkinter as tk
from tkinter import messagebox, filedialog
import os

# Function to XOR each byte of the image data with the key
def xor_encrypt_decrypt(image_data, key):
    key = key.encode('utf-8')
    encrypted_decrypted_data = bytearray()
    for i in range(len(image_data)):
        encrypted_decrypted_data.append(image_data[i] ^ key[i % len(key)])
    return encrypted_decrypted_data

# Function to save binary data to a file
def save_to_file_binary(folder, filename, data):
    with open(os.path.join(folder, filename), 'wb') as file:
        file.write(data)

# Function to load binary data from a file
def load_from_file_binary(filepath):
    with open(filepath, 'rb') as file:
        return file.read()

# Function to encrypt image
def encrypt_image():
    filepath = filedialog.askopenfilename()
    if filepath:
        image_data = load_from_file_binary(filepath)
        key = key_entry.get()
        if key:
            encrypted_data = xor_encrypt_decrypt(image_data, key)
            folder = filedialog.askdirectory()
            if folder:
                filename = os.path.basename(filepath)
                save_to_file_binary(folder, 'encrypted_' + filename, encrypted_data)
                # Save the key in a text file within the output folder
                with open(os.path.join(folder, 'key.txt'), 'w') as key_file:
                    key_file.write(key)
                messagebox.showinfo("Success", "Image encrypted successfully!\nKey saved in 'key.txt'.")
        else:
            messagebox.showerror("Error", "Please enter a key.")

# Function to decrypt image
def decrypt_image():
    filepath = filedialog.askopenfilename()
    if filepath:
        encrypted_data = load_from_file_binary(filepath)
        key = key_entry.get()
        if key:
            decrypted_data = xor_encrypt_decrypt(encrypted_data, key)
            folder = filedialog.askdirectory()
            if folder:
                filename = os.path.basename(filepath)
                save_to_file_binary(folder, 'decrypted_' + filename, decrypted_data)
                messagebox.showinfo("Success", "Image decrypted successfully!")
        else:
            messagebox.showerror("Error", "Please enter the decryption key.")

# Creating main window
root = tk.Tk()
root.title("Image Encryption and Decryption with XOR")

# Creating frame for input and buttons
frame = tk.Frame(root)
frame.pack(pady=20)

# Creating entry widget for key input (used for both encryption and decryption)
key_label = tk.Label(frame, text="Enter Key:")
key_label.pack(side=tk.TOP)
key_entry = tk.Entry(frame, width=50)
key_entry.pack(side=tk.TOP, pady=10)

# Creating frame for buttons
button_frame = tk.Frame(frame)
button_frame.pack(pady=10)

# Creating buttons for selecting image and triggering encryption and decryption of images
select_encrypt_button = tk.Button(button_frame, text="Select Image to Encrypt", command=encrypt_image)
select_encrypt_button.pack(side=tk.LEFT, padx=10)

select_decrypt_button = tk.Button(button_frame, text="Select Image to Decrypt", command=decrypt_image)
select_decrypt_button.pack(side=tk.RIGHT, padx=10)

# Running the application
root.mainloop()
