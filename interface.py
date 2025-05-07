from tkinter import filedialog
import tempfile
import os
import tkinter as tk
import numpy as np
from tkinter import ttk, messagebox
from sympy import mod_inverse
from methods.Caesar_Cipher import encryption as caesar_encrypt, decryption as caesar_decrypt, brute_force_decrypt as caesar_brute_force
from methods.Affine import encrypt as affine_encrypt, decrypt as affine_decrypt, get_valid_a_values
from methods.One_Time_Pad import encrypt as otp_encrypt, decrypt as otp_decrypt
from methods.Rail_Fence import encrypt as railfence_encrypt, decrypt as railfence_decrypt
from methods.Vigenere import encryption as vigenere_encrypt, decryption as vigenere_decrypt
from methods.ColumanrCipher import encrypt as columnar_encrypt, decrypt as columnar_decrypt
from methods.HillCipher import encrypt as hill_encrypt,decrypt as hill_decrypt,matrix_mod_inv
from methods.desCipher import encrypt as des_encrypt, decrypt as des_decrypt
from methods.rsaCipher import generate_keys, encrypt as rsa_encrypt, decrypt as rsa_decrypt

class CryptographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Tool")
        self.root.geometry("800x700")
        self.key_matrix = None
        self.rsa_private_key = None
        self.rsa_public_key = None
        
        # Initialize variables
        self.operation_var = tk.StringVar(value="encryption")
        self.method_var = tk.StringVar(value="caesar")
        self.key_var = tk.StringVar()
        self.a_var = tk.StringVar()
        self.b_var = tk.StringVar()
        
        # Configure theme and create widgets
        self.setup_dark_theme()
        self.create_widgets()
        
        # Track changes
        self.operation_var.trace_add('write', self.update_labels)
        self.method_var.trace_add('write', self.update_key_requirements)
        
        # Initial update
        self.update_labels()
        self.update_key_requirements()
    
    def setup_dark_theme(self):
        self.root.tk_setPalette(background='#2d2d2d', foreground='#e6e6e6',
                                activeBackground='#3d3d3d', activeForeground='#ffffff')
        
        style = ttk.Style()
        style.theme_use('alt')
        
        style.configure('.', background='#2d2d2d', foreground='#e6e6e6')
        style.configure('TFrame', background='#2d2d2d')
        style.configure('TLabelFrame', background='#2d2d2d', foreground='#e6e6e6')
        style.configure('TLabelFrame.Label', background='#2d2d2d', foreground='#e6e6e6')
        style.configure('TRadiobutton', background='#2d2d2d', foreground='#247a92')
        style.configure('TButton', background='#3d3d3d', foreground='#e6e6e6')
        style.configure('TEntry', fieldbackground='#3d3d3d', foreground='#e6e6e6')
        
        style.map('TButton',
                background=[('active', '#4d4d4d'), ('pressed', '#1d1d1d')],
                foreground=[('active', '#ffffff')])
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Operation selection
        operation_frame = ttk.LabelFrame(main_frame, text="Operation", padding=10)
        operation_frame.pack(pady=5, fill="x")
        
        ttk.Radiobutton(operation_frame, text="Encryption", variable=self.operation_var, 
                        value="encryption").pack(side="left", padx=5)
        ttk.Radiobutton(operation_frame, text="Decryption", variable=self.operation_var, 
                        value="decryption").pack(side="left", padx=5)
        
        # Method selection
        method_frame = ttk.LabelFrame(main_frame, text="Method", padding=10)
        method_frame.pack(pady=5, fill="x")
        
        methods = ["Caesar", "Affine", "One-Time Pad", "Rail Fence","Vigenere","Columnar", "Hill","DES","RSA"]
        for method in methods:
            ttk.Radiobutton(method_frame, text=method, variable=self.method_var, 
                            value=method.lower().replace('-', '').replace(' ', '')).pack(side="left", padx=5)
        
        # Key input area
        self.key_frame = ttk.LabelFrame(main_frame, text="Key Parameters", padding=10)
        self.key_frame.pack(pady=5, fill="x")
        
        # Caesar key input (default)
        self.caesar_frame = ttk.Frame(self.key_frame)
        ttk.Label(self.caesar_frame, text="Shift Key (0-25):").pack(side="left")
        ttk.Entry(self.caesar_frame, textvariable=self.key_var, width=5).pack(side="left", padx=5)
        self.caesar_frame.pack(fill="x")
        
        # Affine key inputs
        self.affine_frame = ttk.Frame(self.key_frame)
        ttk.Label(self.affine_frame, text="a:").pack(side="left")
        ttk.Entry(self.affine_frame, textvariable=self.a_var, width=5).pack(side="left", padx=5)
        ttk.Label(self.affine_frame, text="b:").pack(side="left")
        ttk.Entry(self.affine_frame, textvariable=self.b_var, width=5).pack(side="left", padx=5)
        ttk.Label(self.affine_frame, text=f"Valid 'a' values: {', '.join(map(str, get_valid_a_values()))}").pack(side="left", padx=10)
        self.affine_frame.pack(fill="x")
        self.affine_frame.pack_forget()  # Hide initially
        
        # # OTP key input
        self.otp_frame = ttk.Frame(self.key_frame)
        ttk.Label(self.otp_frame, text="Key String:").pack(side="left")
        ttk.Entry(self.otp_frame, textvariable=self.key_var, width=50).pack(side="left", padx=5)
        self.otp_frame.pack(fill="x")
        self.otp_frame.pack_forget()  # Hide initiallyr
        
        # Rail Fence key input
        self.rail_frame = ttk.Frame(self.key_frame)
        ttk.Label(self.rail_frame, text="Number of Rails (≥2):").pack(side="left")
        ttk.Entry(self.rail_frame, textvariable=self.key_var, width=5).pack(side="left", padx=5)
        self.rail_frame.pack(fill="x")
        self.rail_frame.pack_forget()  # Hide initially
        # Vigenère key input
        self.vigenere_frame = ttk.Frame(self.key_frame)
        ttk.Label(self.vigenere_frame, text="Key String:").pack(side="left")
        ttk.Entry(self.vigenere_frame, textvariable=self.key_var, width=50).pack(side="left", padx=5)
        self.vigenere_frame.pack(fill="x")
        self.vigenere_frame.pack_forget()
        # Hill cipher key input
        self.hill_frame = ttk.LabelFrame(self.key_frame, text="Hill Cipher Key Matrix", padding=10)
        
        self.matrix_entries = []
        matrix_frame = ttk.Frame(self.hill_frame)
        for i in range(2):
            row_frame = ttk.Frame(matrix_frame)
            for j in range(2):
                var = tk.StringVar()
                entry = ttk.Entry(row_frame, textvariable=var, width=3)
                entry.pack(side="left", padx=2)
                self.matrix_entries.append(var)
            row_frame.pack()
        matrix_frame.pack()
        
        ttk.Button(self.hill_frame, text="Validate Matrix", 
                    command=self.validate_hill_matrix).pack(pady=5)
        self.hill_status = ttk.Label(self.hill_frame, text="Enter 2x2 matrix values (0-25)")
        self.hill_status.pack()
        
        self.hill_frame.pack(fill="x")
        self.hill_frame.pack_forget()  # Hide initially
        # Columnar Transposition key input
        self.columnar_frame = ttk.LabelFrame(self.key_frame, text="Columnar Key", padding=10)
        ttk.Label(self.columnar_frame, text="Enter keyword:").pack(side="left")
        self.columnar_key_var = tk.StringVar()
        ttk.Entry(self.columnar_frame, textvariable=self.columnar_key_var, width=20).pack(side="left", padx=5)
        self.columnar_frame.pack(fill="x")
        self.columnar_frame.pack_forget()  # Hide initially
        # DES key input
        self.des_frame = ttk.LabelFrame(self.key_frame, text="DES Key (8 chars)", padding=10)
        ttk.Label(self.des_frame, text="Enter 8-character key:").pack(side="left")
        self.des_key_var = tk.StringVar()
        ttk.Entry(self.des_frame, textvariable=self.des_key_var, width=12).pack(side="left", padx=5)
        self.des_frame.pack(fill="x")
        self.des_frame.pack_forget()  # Hide initially

        # RSA key management
        self.rsa_frame = ttk.LabelFrame(self.key_frame, text="RSA Key Management", padding=10)
        # Key generation button
        ttk.Button(self.rsa_frame, text="Generate Key Pair", 
                    command=self.generate_rsa_keys).pack(pady=5)
        # Key display area
        self.rsa_key_status = ttk.Label(self.rsa_frame, text="No RSA keys generated")
        self.rsa_key_status.pack()
        # Public key file button
        ttk.Button(self.rsa_frame, text="Save Public Key", 
                    command=self.save_public_key).pack(side="left", padx=5)
        # Private key file button
        ttk.Button(self.rsa_frame, text="Save Private Key", 
                    command=self.save_private_key).pack(side="left", padx=5)
        self.rsa_frame.pack(fill="x")
        self.rsa_frame.pack_forget()  # Hide initially
        
        # Text areas
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(pady=10, fill="both", expand=True)
        
        # Input text area
        self.input_frame = ttk.LabelFrame(text_frame, padding=10)
        self.input_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        self.input_text = tk.Text(self.input_frame, height=15, wrap="word", 
                                bg="#3d3d3d", fg="#e6e6e6", insertbackground="white")
        self.input_text.pack(fill="both", expand=True)
        
        # Output text area (read-only)
        self.output_frame = ttk.LabelFrame(text_frame, padding=10)
        self.output_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        self.output_text = tk.Text(self.output_frame, height=15, wrap="word", 
                                    bg="#3d3d3d", fg="#e6e6e6", insertbackground="white",
                                    state="disabled")
        self.output_text.pack(fill="both", expand=True)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10, fill="x")
        
        ttk.Button(button_frame, text="Process", command=self.process_text).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_text).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Copy Result", command=self.copy_result).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Swap Text", command=self.swap_text).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Brute Force", command=self.brute_force).pack(side="right", padx=5)
    def validate_hill_matrix(self):
        """Validate the Hill cipher key matrix"""
        try:
            key_numbers = []
            for var in self.matrix_entries:
                num = int(var.get())
                if num < 0 or num > 25:
                    raise ValueError("Numbers must be between 0-25")
                key_numbers.append(num)
            
            self.key_matrix = np.array([
                [key_numbers[0], key_numbers[1]],
                [key_numbers[2], key_numbers[3]]
            ])
            
            # Check if matrix is invertible
            matrix_mod_inv(self.key_matrix, 26)
            self.hill_status.config(text="✓ Valid key matrix", foreground="green")
            return True
        except Exception as e:
            self.hill_status.config(text=f"Invalid matrix: {str(e)}", foreground="red")
            return False
    def update_labels(self, *args):
        operation = self.operation_var.get()
        if operation == "encryption":
            self.input_frame.config(text="Plain Text")
            self.output_frame.config(text="Chiper Text")
        else:
            self.input_frame.config(text="Chiper Text")
            self.output_frame.config(text="Orginal Text")
    def generate_rsa_keys(self):
        """Generate new RSA key pair"""
        try:
            self.rsa_private_key, self.rsa_public_key = generate_keys()
            self.rsa_key_status.config(
                text="✓ RSA keys generated (2048-bit)",
                foreground="green"
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")
    def save_public_key(self):
        """Save public key to file"""
        if not self.rsa_public_key:
            messagebox.showwarning("Warning", "No public key generated yet")
            return
        
        filename = filedialog.asksaveasfilename(
        title="Save Public Key",
        defaultextension=".txt",  # Optional: set a default file extension
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]  # Optional: filter file types
        )

        # Check if a file was selected (user didn't cancel the dialog)
        if filename:
            print("Selected file:", filename)
        else:
            print("No file selected")
    def save_private_key(self):
        """Save private key to file"""
        if not self.rsa_private_key:
            messagebox.showwarning("Warning", "No private key generated yet")
            return
        
        filename = filedialog.asksaveasfilename(
        title="Save Private Key",
        defaultextension=".txt",  # Optional: set a default file extension
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]  # Optional: filter file types
        )

        # Check if a file was selected (user didn't cancel the dialog)
        if filename:
            print("Selected file:", filename)
        else:
            print("No file selected")
    
    def update_key_requirements(self, *args):
        method = self.method_var.get()
        
        # Hide all key frames first
        self.caesar_frame.pack_forget()
        self.affine_frame.pack_forget()
        self.otp_frame.pack_forget()
        self.rail_frame.pack_forget()
        self.vigenere_frame.pack_forget()
        self.hill_frame.pack_forget()
        self.columnar_frame.pack_forget()
        self.des_frame.pack_forget()
        self.rsa_frame.pack_forget()
        # Show the appropriate key frame
        if method == "caesar":
            self.caesar_frame.pack(fill="x")
        elif method == "affine":
            self.affine_frame.pack(fill="x")
        elif method == "onetimepad":
            self.otp_frame.pack(fill="x")
        elif method == "railfence":
            self.rail_frame.pack(fill="x")
        elif method == "vigenere":
            self.vigenere_frame.pack(fill="x")
        elif method == "columnar":
            self.columnar_frame.pack(fill="x")
        elif method == "hill":
            self.hill_frame.pack(fill="x")
        elif method == "des":
            self.des_frame.pack(fill="x")
        elif method == "rsa":
            self.rsa_frame.pack(fill="x")
    def process_text(self):
        operation = self.operation_var.get()
        method = self.method_var.get()
        input_text = self.input_text.get("1.0", "end-1c")
        
        if not input_text:
            messagebox.showwarning("Warning", "Please enter some text to process")
            return
            
        try:
            if method == "caesar":
                key = int(self.key_var.get())
                if operation == "encryption":
                    result = caesar_encrypt(input_text, key)
                else:
                    result = caesar_decrypt(input_text, key)
                    
            elif method == "affine":
                a = int(self.a_var.get())
                b = int(self.b_var.get())
                mod_inverse(a, 26)  # Validate 'a' has inverse
                if operation == "encryption":
                    result = affine_encrypt(input_text, a, b)
                else:
                    result = affine_decrypt(input_text, a, b)
                    
            elif method == "onetimepad":
                key = self.key_var.get()
                if not key:
                    raise ValueError("Please enter a key string")
                if operation == "encryption":
                    result = otp_encrypt(input_text, key)
                else:
                    result = otp_decrypt(input_text, key)
                    
            elif method == "railfence":
                rails = int(self.key_var.get())
                if rails < 2:
                    raise ValueError("Number of rails must be at least 2")
                if operation == "encryption":
                    result = railfence_encrypt(input_text, rails)
                else:
                    result = railfence_decrypt(input_text, rails)
            
            elif method == "vigenere":
                key = self.key_var.get()
                if not key:
                    raise ValueError("Please enter a key string")
                
                if operation == "encryption":
                    result = vigenere_encrypt(input_text, key)
                else:
                    result = vigenere_decrypt(input_text, key)
            
            elif method == "columnar":
                key = self.columnar_key_var.get()
                if not key:
                    raise ValueError("Please enter a Columnar key")
                
                if operation == "encryption":
                    result = columnar_encrypt(input_text, key)
                else:
                    result = columnar_decrypt(input_text, key)
            
            elif method == "hill":
                if not self.validate_hill_matrix():
                    raise ValueError("Invalid Hill cipher matrix")
                
                if operation == "encryption":
                    result = hill_encrypt(input_text, self.key_matrix)
                else:
                    result = hill_decrypt(input_text, self.key_matrix)        
            
            elif method == "des":
                key = self.des_key_var.get()
                if len(key) != 8:
                    raise ValueError("DES key must be exactly 8 characters long")
                
                if operation == "encryption":
                    result = des_encrypt(input_text, key)
                    # DES returns bytes - convert to hex for display
                    result = result.hex()
                else:
                    # Convert hex string back to bytes for decryption
                    try:
                        ciphertext = bytes.fromhex(input_text)
                    except ValueError:
                        raise ValueError("Invalid ciphertext format - must be hex string")
                    result = des_decrypt(ciphertext, key)
            elif method == "rsa":
                if operation == "encryption":
                    if not self.rsa_public_key:
                        raise ValueError("No RSA public key generated")
                    result = rsa_encrypt(input_text, self.rsa_public_key)
                else:
                    if not self.rsa_private_key:
                        raise ValueError("No RSA private key generated")
                    result = rsa_decrypt(input_text, self.rsa_private_key)
            else:
                result = f"Method {method} not implemented yet"
            self.update_output(result)
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def brute_force(self):
        method = self.method_var.get()
        input_text = self.input_text.get("1.0", "end-1c")
        
        if not input_text:
            messagebox.showwarning("Warning", "Please enter some text to process")
            return
            
        try:
            if method == "caesar":
                result = caesar_brute_force(input_text)
            else:
                result = f"Brute force not available for {method} method"
            
            self.update_output(result)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def update_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", text)
        self.output_text.config(state="disabled")
    
    def clear_text(self):
        self.input_text.delete("1.0", "end")
        self.update_output("")
        self.key_var.set("")
        self.a_var.set("")
        self.b_var.set("")
    
    def copy_result(self):
        self.output_text.config(state="normal")
        result = self.output_text.get("1.0", "end-1c")
        self.output_text.config(state="disabled")
        
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Info", "Result copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No result to copy")
    
    def swap_text(self):
        input_content = self.input_text.get("1.0", "end-1c")
        
        self.output_text.config(state="normal")
        output_content = self.output_text.get("1.0", "end-1c")
        self.output_text.config(state="disabled")
        
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", output_content)
        self.update_output(input_content)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptographyApp(root)
    root.mainloop()