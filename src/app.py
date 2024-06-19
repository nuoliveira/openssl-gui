import hashlib
import traceback
from OpenSSL import crypto
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


class App:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("OpenSSL GUI")
        self.root.geometry("800x600")

        self.main_frame = MainFrame(self.root)
        self.main_frame.pack(fill="both", expand=True)

    def run(self) -> None:
        self.root.mainloop()


class MainFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.notebook = ttk.Notebook(self)
        self.notebook.add(ViewCertificateFrame(self.notebook), text="View Certificate")
        self.notebook.add(VerifyFileIntegrityFrame(self.notebook), text="Verify File Integrity")
        self.notebook.add(CreateKeyPairFrame(self.notebook), text="Create Key Pair")
        self.notebook.add(CreateCertificateSigningRequestFrame(self.notebook), text="Create Certificate Signing Request")
        self.notebook.add(CreateCertificateFrame(self.notebook), text="Create Certificate")
        self.notebook.pack(fill="both", expand=True)


class VerifyFileIntegrityFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self) -> None:
        self.input_file_frame = ttk.Labelframe(self, text="Input")
        
        self.input_file_label = ttk.Label(self.input_file_frame, text="File")
        self.input_file_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.input_file_input = ttk.Entry(self.input_file_frame, state="readonly")
        self.input_file_input.grid(row=0, column=1, padx=5, pady=5)
        self.input_file_browse_button = ttk.Button(self.input_file_frame, text="Browse", command=self._browse_input_file)
        self.input_file_browse_button.grid(row=0, column=2, padx=5, pady=5)

        self.hash_algorithm_label = ttk.Label(self.input_file_frame, text="Hash Algorithm")
        self.hash_algorithm_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.hash_algorithm_input = ttk.Combobox(self.input_file_frame, values=tuple(hashlib.algorithms_available), state="readonly")
        self.hash_algorithm_input.grid(row=1, column=1, padx=5, pady=5)

        self.verify_file_button = ttk.Button(self.input_file_frame, text="Verify", command=self._verify_file_integrity)
        self.verify_file_button.grid(row=2, columnspan=3, padx=5, pady=5)

        self.input_file_frame.pack(fill="x", padx=10, pady=10)

    def _browse_input_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not filename:
            return
        self.input_file_input.config(state="normal")
        self.input_file_input.delete(0, "end")
        self.input_file_input.insert(0, filename)
        self.input_file_input.config(state="readonly")

    def _verify_file_integrity(self) -> None:
        try:
            with open(self.input_file_input.get(), "rb") as input_file:
                file_hash = hashlib.file_digest(input_file, self.hash_algorithm_input.get())
            messagebox.showinfo("File Hash", file_hash.hexdigest())
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))


class CreateKeyPairFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self) -> None:
        self.key_frame = ttk.Labelframe(self, text="Key Pair")

        self.public_key_label = ttk.Label(self.key_frame, text="Public Key")
        self.public_key_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.public_key_input = ttk.Entry(self.key_frame, state="readonly")
        self.public_key_input.grid(row=0, column=1, padx=5, pady=5)
        self.public_key_browse_button = ttk.Button(self.key_frame, text="Browse", command=self._browse_public_key)
        self.public_key_browse_button.grid(row=0, column=2, padx=5, pady=5)

        self.private_key_label = ttk.Label(self.key_frame, text="Private Key")
        self.private_key_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.private_key_input = ttk.Entry(self.key_frame, state="readonly")
        self.private_key_input.grid(row=1, column=1, padx=5, pady=5)
        self.private_key_browse_button = ttk.Button(self.key_frame, text="Browse", command=self._browse_private_key)
        self.private_key_browse_button.grid(row=1, column=2, padx=5, pady=5)

        self.key_pair_type_label = ttk.Label(self.key_frame, text="Key Pair Type")
        self.key_pair_type_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.key_pair_type_input = ttk.Combobox(self.key_frame, values=("RSA", "DSA"), state="readonly")
        self.key_pair_type_input.grid(row=2, column=1, padx=5, pady=5)

        self.key_pair_size_label = ttk.Label(self.key_frame, text="Key Pair Size")
        self.key_pair_size_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.key_pair_size_input = ttk.Combobox(self.key_frame, values=("512", "1024", "2048", "4096"), state="readonly")
        self.key_pair_size_input.grid(row=3, column=1, padx=5, pady=5)

        self.key_pair_create_button = ttk.Button(self.key_frame, text="Create Key Pair", command=self._create_keypair)
        self.key_pair_create_button.grid(row=4, columnspan=3, padx=5, pady=5)

        self.key_frame.pack(fill="x", padx=10, pady=10)

    def _browse_public_key(self) -> None:
        filename = filedialog.asksaveasfilename(filetypes=[("Public Key", "*.pub")])
        if not filename:
            return
        self.public_key_input.config(state="normal")
        self.public_key_input.delete(0, "end")
        self.public_key_input.insert(0, filename)
        self.public_key_input.config(state="readonly")

    def _browse_private_key(self) -> None:
        filename = filedialog.asksaveasfilename(filetypes=[("Private Key", "*.key")])
        if not filename:
            return
        self.private_key_input.config(state="normal")
        self.private_key_input.delete(0, "end")
        self.private_key_input.insert(0, filename)
        self.private_key_input.config(state="readonly")

    def _create_keypair(self) -> None:
        try:
            public_key_file_path = self.public_key_input.get()
            private_key_file_path = self.private_key_input.get()
            key_pair_type = self.key_pair_type_input.get()
            key_pair_size = int(self.key_pair_size_input.get())

            key_pair = crypto.PKey()
            if key_pair_type == "RSA":
                key_pair.generate_key(crypto.TYPE_RSA, key_pair_size)
            elif key_pair_type == "DSA":
                key_pair.generate_key(crypto.TYPE_DSA, key_pair_size)

            with open(public_key_file_path, "wb") as public_key_file:
                public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair))
            with open(private_key_file_path, "wb") as private_key_file:
                private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))

            messagebox.showinfo("Success", "Key pair created successfully!")
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))


class ViewCertificateFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self) -> None:
        self.certificate_frame = ttk.Labelframe(self, text="Certificate")
        self.certificate_label = ttk.Label(self.certificate_frame, text="Certificate")
        self.certificate_file_input = ttk.Entry(self.certificate_frame, state="readonly")
        self.certificate_browse_button = ttk.Button(self.certificate_frame, text="Browse", command=self._browse_certificate)

        self.certificate_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.certificate_file_input.grid(row=0, column=1, padx=5, pady=5)
        self.certificate_browse_button.grid(row=0, column=2, padx=5, pady=5)

        self.certificate_frame.pack(fill="x", padx=10, pady=10)

        self.subject_frame = ttk.LabelFrame(self, text="Subject")
        self.create_subject_widgets()
        self.subject_frame.pack(fill="x", padx=10, pady=10)

        self.issuer_frame = ttk.LabelFrame(self, text="Issuer")
        self.create_issuer_widgets()
        self.issuer_frame.pack(fill="x", padx=10, pady=10)

        self.validity_frame = ttk.LabelFrame(self, text="Validity")
        self.create_validity_widgets()
        self.validity_frame.pack(fill="x", padx=10, pady=10)

        self.public_key_frame = ttk.LabelFrame(self, text="Public Key")
        self.create_public_key_widgets()
        self.public_key_frame.pack(fill="x", padx=10, pady=10)

    def create_subject_widgets(self) -> None:
        labels = ["Common Name", "Email Address", "Country", "State or Province", "Locality", "Organization", "Organization Unit"]
        self.subject_labels = {}
        self.subject_values = {}
        for i, label in enumerate(labels):
            self.subject_labels[label] = ttk.Label(self.subject_frame, text=label)
            self.subject_values[label] = ttk.Label(self.subject_frame)
            self.subject_labels[label].grid(row=i, column=0, padx=5, pady=2, sticky="e")
            self.subject_values[label].grid(row=i, column=1, padx=5, pady=2, sticky="w")

    def create_issuer_widgets(self) -> None:
        labels = ["Common Name", "Email Address", "Country", "State or Province", "Locality", "Organization", "Organization Unit"]
        self.issuer_labels = {}
        self.issuer_values = {}
        for i, label in enumerate(labels):
            self.issuer_labels[label] = ttk.Label(self.issuer_frame, text=label)
            self.issuer_values[label] = ttk.Label(self.issuer_frame)
            self.issuer_labels[label].grid(row=i, column=0, padx=5, pady=2, sticky="e")
            self.issuer_values[label].grid(row=i, column=1, padx=5, pady=2, sticky="w")

    def create_validity_widgets(self) -> None:
        labels = ["Not Before", "Not After"]
        self.validity_labels = {}
        self.validity_values = {}
        for i, label in enumerate(labels):
            self.validity_labels[label] = ttk.Label(self.validity_frame, text=label)
            self.validity_values[label] = ttk.Label(self.validity_frame)
            self.validity_labels[label].grid(row=i, column=0, padx=5, pady=2, sticky="e")
            self.validity_values[label].grid(row=i, column=1, padx=5, pady=2, sticky="w")

    def create_public_key_widgets(self) -> None:
        labels = ["Algorithm", "Key Size"]
        self.public_key_labels = {}
        self.public_key_values = {}
        for i, label in enumerate(labels):
            self.public_key_labels[label] = ttk.Label(self.public_key_frame, text=label)
            self.public_key_values[label] = ttk.Label(self.public_key_frame)
            self.public_key_labels[label].grid(row=i, column=0, padx=5, pady=2, sticky="e")
            self.public_key_values[label].grid(row=i, column=1, padx=5, pady=2, sticky="w")

    def _browse_certificate(self) -> None:
        certificate_file = filedialog.askopenfile("rb", filetypes=[("All Files", "*.*")])
        if not certificate_file:
            return

        self.certificate_file_input.config(state="normal")
        self.certificate_file_input.delete(0, "end")
        self.certificate_file_input.insert(0, certificate_file.name)
        self.certificate_file_input.config(state="readonly")

        certificate_data = certificate_file.read()
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_data)
        self._update_certificate_info(certificate)

        certificate_file.close()  # Ensure to close the file after reading

    def _update_certificate_info(self, certificate) -> None:
        subject = certificate.get_subject()
        self.subject_values["Common Name"].config(text=subject.commonName)
        self.subject_values["Email Address"].config(text=subject.emailAddress)
        self.subject_values["Country"].config(text=subject.countryName)
        self.subject_values["State or Province"].config(text=subject.stateOrProvinceName)
        self.subject_values["Locality"].config(text=subject.localityName)
        self.subject_values["Organization"].config(text=subject.organizationName)
        self.subject_values["Organization Unit"].config(text=subject.organizationalUnitName)

        issuer = certificate.get_issuer()
        self.issuer_values["Common Name"].config(text=issuer.commonName)
        self.issuer_values["Email Address"].config(text=issuer.emailAddress)
        self.issuer_values["Country"].config(text=issuer.countryName)
        self.issuer_values["State or Province"].config(text=issuer.stateOrProvinceName)
        self.issuer_values["Locality"].config(text=issuer.localityName)
        self.issuer_values["Organization"].config(text=issuer.organizationName)
        self.issuer_values["Organization Unit"].config(text=issuer.organizationalUnitName)

        self.validity_values["Not Before"].config(text=certificate.get_notBefore().decode())
        self.validity_values["Not After"].config(text=certificate.get_notAfter().decode())

        public_key = certificate.get_pubkey()
        self.public_key_values["Algorithm"].config(text=public_key.type())
        self.public_key_values["Key Size"].config(text=public_key.bits())



class CreateCertificateFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self) -> None:
        self.cert_frame = ttk.Labelframe(self, text="Create Certificate")

        self.csr_label = ttk.Label(self.cert_frame, text="CSR File")
        self.csr_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.csr_entry = ttk.Entry(self.cert_frame, state="readonly", width=50)
        self.csr_entry.grid(row=0, column=1, padx=5, pady=5)
        self.csr_browse_button = ttk.Button(self.cert_frame, text="Browse", command=self._browse_csr)
        self.csr_browse_button.grid(row=0, column=2, padx=5, pady=5)

        self.key_label = ttk.Label(self.cert_frame, text="Private Key File")
        self.key_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.key_entry = ttk.Entry(self.cert_frame, state="readonly", width=50)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)
        self.key_browse_button = ttk.Button(self.cert_frame, text="Browse", command=self._browse_key)
        self.key_browse_button.grid(row=1, column=2, padx=5, pady=5)

        self.validity_label = ttk.Label(self.cert_frame, text="Validity (Days)")
        self.validity_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.validity_entry = ttk.Entry(self.cert_frame, width=10)
        self.validity_entry.grid(row=2, column=1, padx=5, pady=5)

        self.create_cert_button = ttk.Button(self.cert_frame, text="Create Certificate", command=self._create_certificate)
        self.create_cert_button.grid(row=3, columnspan=3, padx=5, pady=10)

        self.cert_frame.pack(padx=20, pady=20, fill="both", expand=True)

    def _browse_csr(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("CSR files", "*.csr"), ("All Files", "*.*")])
        if filename:
            self.csr_entry.config(state="normal")
            self.csr_entry.delete(0, "end")
            self.csr_entry.insert(0, filename)
            self.csr_entry.config(state="readonly")

    def _browse_key(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("Key files", "*.key"), ("All Files", "*.*")])
        if filename:
            self.key_entry.config(state="normal")
            self.key_entry.delete(0, "end")
            self.key_entry.insert(0, filename)
            self.key_entry.config(state="readonly")

    def _create_certificate(self) -> None:
        csr_filename = self.csr_entry.get().strip()
        key_filename = self.key_entry.get().strip()
        validity_days = self.validity_entry.get().strip()

        if not (csr_filename and key_filename and validity_days.isdigit()):
            messagebox.showerror("Error", "Please fill in all fields correctly.")
            return

        validity_days = int(validity_days)

        # Load CSR
        with open(csr_filename, "rb") as f:
            csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, f.read())

        # Load Private Key
        with open(key_filename, "rb") as f:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        # Create Certificate
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validity_days * 24 * 60 * 60)  # Validity in seconds

        # Add extensions if needed (example with basicConstraints and subjectKeyIdentifier)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])

        cert.set_issuer(cert.get_subject())  # Self-signed certificate
        cert.sign(key, "sha256")

        # Save Certificate to a file
        filename = filedialog.asksaveasfilename(defaultextension=".crt", filetypes=[("Certificate files", "*.crt"), ("All Files", "*.*")])
        if filename:
            with open(filename, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            messagebox.showinfo("Success", f"Certificate created successfully and saved to {filename}")



class CreateCertificateSigningRequestFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self) -> None:
        self.csr_frame = ttk.Labelframe(self, text="Create CSR")

        self.common_name_label = ttk.Label(self.csr_frame, text="Common Name")
        self.common_name_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.common_name_entry = ttk.Entry(self.csr_frame)
        self.common_name_entry.grid(row=0, column=1, padx=5, pady=5)

        self.email_label = ttk.Label(self.csr_frame, text="Email Address")
        self.email_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.email_entry = ttk.Entry(self.csr_frame)
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)

        self.country_label = ttk.Label(self.csr_frame, text="Country")
        self.country_label.grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.country_entry = ttk.Entry(self.csr_frame)
        self.country_entry.grid(row=2, column=1, padx=5, pady=5)

        self.state_label = ttk.Label(self.csr_frame, text="State or Province")
        self.state_label.grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.state_entry = ttk.Entry(self.csr_frame)
        self.state_entry.grid(row=3, column=1, padx=5, pady=5)

        self.locality_label = ttk.Label(self.csr_frame, text="Locality")
        self.locality_label.grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.locality_entry = ttk.Entry(self.csr_frame)
        self.locality_entry.grid(row=4, column=1, padx=5, pady=5)

        self.organization_label = ttk.Label(self.csr_frame, text="Organization")
        self.organization_label.grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.organization_entry = ttk.Entry(self.csr_frame)
        self.organization_entry.grid(row=5, column=1, padx=5, pady=5)

        self.organizational_unit_label = ttk.Label(self.csr_frame, text="Organizational Unit")
        self.organizational_unit_label.grid(row=6, column=0, padx=5, pady=5, sticky="e")
        self.organizational_unit_entry = ttk.Entry(self.csr_frame)
        self.organizational_unit_entry.grid(row=6, column=1, padx=5, pady=5)

        self.create_csr_button = ttk.Button(self.csr_frame, text="Create CSR", command=self._create_csr)
        self.create_csr_button.grid(row=7, columnspan=2, padx=5, pady=10)

        self.csr_frame.pack(padx=20, pady=20, fill="both", expand=True)

    def _create_csr(self) -> None:
        common_name = self.common_name_entry.get().strip()
        email_address = self.email_entry.get().strip()
        country = self.country_entry.get().strip()
        state = self.state_entry.get().strip()
        locality = self.locality_entry.get().strip()
        organization = self.organization_entry.get().strip()
        organizational_unit = self.organizational_unit_entry.get().strip()

        if not common_name:
            messagebox.showerror("Error", "Common Name is required.")
            return

        try:
            # Create a key pair
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)

            # Create a CSR
            req = crypto.X509Req()
            subj = req.get_subject()
            subj.commonName = common_name
            
            # Check if email_address is not empty
            if email_address:
                subj.emailAddress = email_address

            # Check if country is not empty
            if country:
                subj.countryName = country

            # Set other fields similarly
            subj.stateOrProvinceName = state
            subj.localityName = locality
            subj.organizationName = organization
            subj.organizationalUnitName = organizational_unit

            req.set_pubkey(key)
            req.sign(key, "sha256")

            # Save the CSR to a file
            filename = filedialog.asksaveasfilename(defaultextension=".csr", filetypes=[("CSR files", "*.csr"), ("All Files", "*.*")])
            if filename:
                with open(filename, "wb") as f:
                    f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
                messagebox.showinfo("Success", f"CSR created successfully and saved to {filename}")

        except OpenSSL.crypto.Error as e:
            messagebox.showerror("OpenSSL Error", f"Error creating CSR: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")



if __name__ == "__main__":
    app = App()
    app.run()
