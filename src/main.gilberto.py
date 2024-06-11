import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import os

class OpenSSLGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenSSL GUI")

        # Create main frame and canvas
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(self.main_frame)
        self.canvas.pack(side="left", fill="both", expand=True)

        self.scrollbar = tk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.scrollable_frame = tk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        # Create widgets in the scrollable frame
        self.create_widgets()

    def create_widgets(self):
        # View Certificate Frame
        self.view_cert_frame = tk.LabelFrame(self.scrollable_frame, text="View Certificate")
        self.view_cert_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.view_cert_frame, text="Certificate Filename:").grid(row=0, column=0, padx=5, pady=5)
        self.cert_filename = tk.Entry(self.view_cert_frame)
        self.cert_filename.grid(row=0, column=1, padx=5, pady=5)

        self.cert_browse_button = tk.Button(self.view_cert_frame, text="Browse", command=self.browse_cert_file)
        self.cert_browse_button.grid(row=0, column=2, padx=5, pady=5)

        self.view_cert_button = tk.Button(self.view_cert_frame, text="View Certificate", command=self.view_certificate)
        self.view_cert_button.grid(row=1, column=0, columnspan=3, pady=5)

        # Create Certificate Frame
        self.create_cert_frame = tk.LabelFrame(self.scrollable_frame, text="Create Certificate")
        self.create_cert_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.create_cert_frame, text="Certificate Filename:").grid(row=0, column=0, padx=5, pady=5)
        self.create_cert_filename = tk.Entry(self.create_cert_frame)
        self.create_cert_filename.grid(row=0, column=1, padx=5, pady=5)

        self.create_cert_browse_button = tk.Button(self.create_cert_frame, text="Browse", command=self.browse_create_cert_file)
        self.create_cert_browse_button.grid(row=0, column=2, padx=5, pady=5)

        tk.Label(self.create_cert_frame, text="Key Filename:").grid(row=1, column=0, padx=5, pady=5)
        self.create_cert_key_filename = tk.Entry(self.create_cert_frame)
        self.create_cert_key_filename.grid(row=1, column=1, padx=5, pady=5)

        self.key_browse_button_create_cert = tk.Button(self.create_cert_frame, text="Browse", command=self.browse_create_cert_key_file)
        self.key_browse_button_create_cert.grid(row=1, column=2, padx=5, pady=5)

        self.create_cert_button = tk.Button(self.create_cert_frame, text="Create Certificate", command=self.create_certificate)
        self.create_cert_button.grid(row=2, column=0, columnspan=3, pady=5)

        # Encrypt File Frame
        self.encrypt_frame = tk.LabelFrame(self.scrollable_frame, text="Encrypt File")
        self.encrypt_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.encrypt_frame, text="File to Encrypt:").grid(row=0, column=0, padx=5, pady=5)
        self.encrypt_filename = tk.Entry(self.encrypt_frame)
        self.encrypt_filename.grid(row=0, column=1, padx=5, pady=5)

        self.encrypt_browse_button = tk.Button(self.encrypt_frame, text="Browse", command=self.browse_encrypt_file)
        self.encrypt_browse_button.grid(row=0, column=2, padx=5, pady=5)

        tk.Label(self.encrypt_frame, text="Output Encrypted File:").grid(row=1, column=0, padx=5, pady=5)
        self.output_encrypt_filename = tk.Entry(self.encrypt_frame)
        self.output_encrypt_filename.grid(row=1, column=1, padx=5, pady=5)

        self.output_encrypt_browse_button = tk.Button(self.encrypt_frame, text="Browse", command=self.browse_output_encrypt_file)
        self.output_encrypt_browse_button.grid(row=1, column=2, padx=5, pady=5)

        self.encrypt_button = tk.Button(self.encrypt_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.grid(row=2, column=0, columnspan=3, pady=5)

        # Decrypt File Frame
        self.decrypt_frame = tk.LabelFrame(self.scrollable_frame, text="Decrypt File")
        self.decrypt_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.decrypt_frame, text="File to Decrypt:").grid(row=0, column=0, padx=5, pady=5)
        self.decrypt_filename = tk.Entry(self.decrypt_frame)
        self.decrypt_filename.grid(row=0, column=1, padx=5, pady=5)

        self.decrypt_browse_button = tk.Button(self.decrypt_frame, text="Browse", command=self.browse_decrypt_file)
        self.decrypt_browse_button.grid(row=0, column=2, padx=5, pady=5)

        tk.Label(self.decrypt_frame, text="Output Decrypted File:").grid(row=1, column=0, padx=5, pady=5)
        self.output_decrypt_filename = tk.Entry(self.decrypt_frame)
        self.output_decrypt_filename.grid(row=1, column=1, padx=5, pady=5)

        self.output_decrypt_browse_button = tk.Button(self.decrypt_frame, text="Browse", command=self.browse_output_decrypt_file)
        self.output_decrypt_browse_button.grid(row=1, column=2, padx=5, pady=5)

        self.decrypt_button = tk.Button(self.decrypt_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.grid(row=2, column=0, columnspan=3, pady=5)

        # Key Pair Generation Frame
        self.key_pair_frame = tk.LabelFrame(self.scrollable_frame, text="Generate Key Pair")
        self.key_pair_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.key_pair_frame, text="Private Key Filename:").grid(row=0, column=0, padx=5, pady=5)
        self.key_pair_priv_filename = tk.Entry(self.key_pair_frame)
        self.key_pair_priv_filename.grid(row=0, column=1, padx=5, pady=5)

        self.key_pair_priv_browse_button = tk.Button(self.key_pair_frame, text="Browse", command=self.browse_key_pair_priv_file)
        self.key_pair_priv_browse_button.grid(row=0, column=2, padx=5, pady=5)

        tk.Label(self.key_pair_frame, text="Public Key Filename:").grid(row=1, column=0, padx=5, pady=5)
        self.key_pair_pub_filename = tk.Entry(self.key_pair_frame)
        self.key_pair_pub_filename.grid(row=1, column=1, padx=5, pady=5)

        self.key_pair_pub_browse_button = tk.Button(self.key_pair_frame, text="Browse", command=self.browse_key_pair_pub_file)
        self.key_pair_pub_browse_button.grid(row=1, column=2, padx=5, pady=5)

        self.generate_key_pair_button = tk.Button(self.key_pair_frame, text="Generate Key Pair", command=self.generate_key_pair)
        self.generate_key_pair_button.grid(row=2, column=0, columnspan=3, pady=5)

        # File Hash Frame
        self.hash_frame = tk.LabelFrame(self.scrollable_frame, text="File Hash")
        self.hash_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(self.hash_frame, text="File to Hash:").grid(row=0, column=0, padx=5, pady=5)
        self.hash_filename = tk.Entry(self.hash_frame)
        self.hash_filename.grid(row=0, column=1, padx=5, pady=5)

        self.hash_browse_button = tk.Button(self.hash_frame, text="Browse", command=self.browse_hash_file)
        self.hash_browse_button.grid(row=0, column=2, padx=5, pady=5)

        self.hash_button = tk.Button(self.hash_frame, text="Generate Hash", command=self.hash_file)
        self.hash_button.grid(row=1, column=0, columnspan=3, pady=5)

    def browse_cert_file(self):
        filename = filedialog.askopenfilename(title="Select Certificate File", filetypes=[("Certificate Files", "*.crt;*.pem"), ("All Files", "*.*")])
        if filename:
            self.cert_filename.insert(0, filename)

    def browse_create_cert_file(self):
        filename = filedialog.asksaveasfilename(title="Save Certificate File", defaultextension=".crt", filetypes=[("Certificate Files", "*.crt"), ("All Files", "*.*")])
        if filename:
            self.create_cert_filename.insert(0, filename)

    def browse_create_cert_key_file(self):
        filename = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if filename:
            self.create_cert_key_filename.insert(0, filename)

    def browse_encrypt_file(self):
        filename = filedialog.askopenfilename(title="Select File to Encrypt", filetypes=[("All Files", "*.*")])
        if filename:
            self.encrypt_filename.insert(0, filename)

    def browse_output_encrypt_file(self):
        filename = filedialog.asksaveasfilename(title="Save Encrypted File", defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if filename:
            self.output_encrypt_filename.insert(0, filename)

    def browse_decrypt_file(self):
        filename = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if filename:
            self.decrypt_filename.insert(0, filename)

    def browse_output_decrypt_file(self):
        filename = filedialog.asksaveasfilename(title="Save Decrypted File", defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec"), ("All Files", "*.*")])
        if filename:
            self.output_decrypt_filename.insert(0, filename)

    def browse_key_pair_priv_file(self):
        filename = filedialog.asksaveasfilename(title="Save Private Key File", defaultextension=".key", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if filename:
            self.key_pair_priv_filename.insert(0, filename)

    def browse_key_pair_pub_file(self):
        filename = filedialog.asksaveasfilename(title="Save Public Key File", defaultextension=".pub", filetypes=[("Key Files", "*.pub"), ("All Files", "*.*")])
        if filename:
            self.key_pair_pub_filename.insert(0, filename)

    def browse_hash_file(self):
        filename = filedialog.askopenfilename(title="Select File to Hash", filetypes=[("All Files", "*.*")])
        if filename:
            self.hash_filename.insert(0, filename)

    def view_certificate(self):
        cert_filename = self.cert_filename.get()
        if not cert_filename:
            messagebox.showerror("Error", "Please select a certificate file.")
            return

        if not os.path.isfile(cert_filename):
            messagebox.showerror("Error", f"File '{cert_filename}' not found.")
            return

        try:
            output = subprocess.check_output(["openssl", "x509", "-in", cert_filename, "-text", "-noout"])
            messagebox.showinfo("Certificate Details", output.decode())
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to view certificate.\n{e}")

    def create_certificate(self):
        cert_filename = self.create_cert_filename.get()
        key_filename = self.create_cert_key_filename.get()
        if not cert_filename or not key_filename:
            messagebox.showerror("Error", "Please select both certificate and key files.")
            return

        if not os.path.isfile(key_filename):
            messagebox.showerror("Error", f"Key file '{key_filename}' not found.")
            return

        try:
            subprocess.run(["openssl", "req", "-new", "-x509", "-key", key_filename, "-out", cert_filename], check=True)
            messagebox.showinfo("Success", f"Certificate saved to {cert_filename}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to create certificate.\n{e}")

    def encrypt_file(self):
        file_to_encrypt = self.encrypt_filename.get()
        output_file = self.output_encrypt_filename.get()
        if not file_to_encrypt or not output_file:
            messagebox.showerror("Error", "Please select both input and output files.")
            return

        if not os.path.isfile(file_to_encrypt):
            messagebox.showerror("Error", f"File '{file_to_encrypt}' not found.")
            return

        try:
            subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", file_to_encrypt, "-out", output_file], check=True)
            messagebox.showinfo("Success", f"File encrypted to {output_file}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to encrypt file.\n{e}")

    def decrypt_file(self):
        file_to_decrypt = self.decrypt_filename.get()
        output_file = self.output_decrypt_filename.get()
        if not file_to_decrypt or not output_file:
            messagebox.showerror("Error", "Please select both input and output files.")
            return

        if not os.path.isfile(file_to_decrypt):
            messagebox.showerror("Error", f"File '{file_to_decrypt}' not found.")
            return

        try:
            subprocess.run(["openssl", "enc", "-aes-256-cbc", "-d", "-in", file_to_decrypt, "-out", output_file], check=True)
            messagebox.showinfo("Success", f"File decrypted to {output_file}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to decrypt file.\n{e}")

    def generate_key_pair(self):
        priv_key_filename = self.key_pair_priv_filename.get()
        pub_key_filename = self.key_pair_pub_filename.get()
        if not priv_key_filename or not pub_key_filename:
            messagebox.showerror("Error", "Please select both private and public key files.")
            return

        try:
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", priv_key_filename], check=True)
            subprocess.run(["openssl", "rsa", "-pubout", "-in", priv_key_filename, "-out", pub_key_filename], check=True)
            messagebox.showinfo("Success", f"Private key saved to {priv_key_filename}.\nPublic key saved to {pub_key_filename}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to generate key pair.\n{e}")

    def hash_file(self):
        file_to_hash = self.hash_filename.get()
        if not file_to_hash:
            messagebox.showerror("Error", "Please select a file to hash.")
            return

        if not os.path.isfile(file_to_hash):
            messagebox.showerror("Error", f"File '{file_to_hash}' not found.")
            return

        try:
            output = subprocess.check_output(["openssl", "dgst", "-sha256", file_to_hash])
            messagebox.showinfo("File Hash", output.decode())
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to hash file.\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = OpenSSLGUI(root)
    root.mainloop()
