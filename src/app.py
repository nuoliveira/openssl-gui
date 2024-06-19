import hashlib
import ssl
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
        self.notebook.add(VerifyFileIntegrityFrame(self.notebook), text="Verify File Integrity")
        self.notebook.add(CreateKeyPairFrame(self.notebook), text="Create Key Pair")
        self.notebook.add(CreateCertificateSigningRequestFrame(self.notebook), text="Create Certificate Signing Request")
        self.notebook.add(CreateCertificateFrame(self.notebook), text="Create Certificate")
        self.notebook.add(ViewCertificateFrame(self.notebook), text="View Certificate")
        self.notebook.pack(fill="both", expand=True)

class VerifyFileIntegrityFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=8)

        self.file_label = ttk.Label(self, text="File:")
        self.file_input = ttk.Entry(self, state="readonly")
        self.file_browse_button = ttk.Button(self, text="Browse", command=self.browse_input_file)
        self.hash_algorithm_label = ttk.Label(self, text="Algorithm:")
        self.hash_algorithm_input = ttk.Combobox(self, values=tuple(hashlib.algorithms_guaranteed), state="readonly")
        self.verify_file_button = ttk.Button(self, text="Verify", command=self.verify_file_integrity)

        self.file_label.grid(row=0, column=0, pady=(0, 4), padx=(0, 2), sticky="e")
        self.file_input.grid(row=0, column=1, pady=(0, 4), padx=(2, 2), sticky="ew")
        self.file_browse_button.grid(row=0, column=2, pady=(0, 4), padx=(2, 0))
        self.hash_algorithm_label.grid(row=1, column=0, pady=(4, 4), padx=(0, 2), sticky="ew")
        self.hash_algorithm_input.grid(row=1, column=1, pady=(4, 4), padx=(2, 0), sticky="ew")
        self.verify_file_button.grid(row=2, column=0, columnspan=2, pady=(4, 0), padx=(0, 0), sticky="ew")

    def browse_input_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not filename:
            return
        self.file_input.config(state="normal")
        self.file_input.delete(0, "end")
        self.file_input.insert(0, filename)
        self.file_input.config(state="readonly")

    def verify_file_integrity(self) -> None:
        try:
            file = open(self.file_input.get(), "rb")
            file_hash = hashlib.file_digest(file, self.hash_algorithm_input.get())
            file.close()
            messagebox.showinfo("File Hash", file_hash.hexdigest())
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

class CreateKeyPairFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=8)

        self.key_pair_type_label = ttk.Label(self, text="Key Pair Type:")
        self.key_pair_type_input = ttk.Combobox(self, values=("RSA",), state="readonly")
        self.key_pair_size_label = ttk.Label(self, text="Key Pair Size:")
        self.key_pair_size_input = ttk.Combobox(self, values=("512", "1024", "2048", "3072", "4096", "5120", "6144", "7168", "8192"), state="readonly")
        self.key_pair_create_button = ttk.Button(self, text="Create Key Pair", command=self.create_keypair)

        self.key_pair_type_label.grid(row=0, column=0, pady=(0, 4), padx=(0, 2), sticky="nse")
        self.key_pair_type_input.grid(row=0, column=1, pady=(0, 4), padx=(2, 0), sticky="nsw")
        self.key_pair_size_label.grid(row=1, column=0, pady=(4, 4), padx=(0, 2), sticky="nse")
        self.key_pair_size_input.grid(row=1, column=1, pady=(4, 4), padx=(2, 0), sticky="nsw")
        self.key_pair_create_button.grid(row=2, column=0, columnspan=2, pady=(4, 0), padx=(0, 0), sticky="nsew")

    def create_keypair(self) -> None:
        try:
            key_pair_type = self.key_pair_type_input.get()
            key_pair_size = int(self.key_pair_size_input.get())

            key_pair = crypto.PKey()
            key_pair.generate_key(crypto.TYPE_RSA, key_pair_size)

            private_key_file = filedialog.asksaveasfile("wb", filetypes=[("Private Key", "*.key")])
            if private_key_file is None:
                return
            private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))
            private_key_file.close()

            public_key_file = filedialog.asksaveasfile("wb", filetypes=[("Public Key", "*.pub")])
            if public_key_file is None:
                return
            public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair))
            public_key_file.close()

            messagebox.showinfo("Create Key Pair", "Key Pair successfully created!")
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

class CreateCertificateSigningRequestFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=8)

        self.private_key_label = ttk.Label(self, text="Private Key:")
        self.private_key_input = ttk.Entry(self, state="readonly")
        self.private_key_browse_button = ttk.Button(self, text="Browse", command=self.browse_private_key_file)
        self.public_key_label = ttk.Label(self, text="Public Key:")
        self.public_key_input = ttk.Entry(self, state="readonly")
        self.public_key_browse_button = ttk.Button(self, text="Browse", command=self.browse_public_key_file)
        self.common_name_label = ttk.Label(self, text="Common Name:")
        self.common_name_input = ttk.Entry(self)
        self.email_address_label = ttk.Label(self, text="Email Address:")
        self.email_address_input = ttk.Entry(self)
        self.country_label = ttk.Label(self, text="Country:")
        self.country_input = ttk.Entry(self)
        self.state_or_province_label = ttk.Label(self, text="State or Province:")
        self.state_or_province_input = ttk.Entry(self)
        self.locality_input = ttk.Entry(self)
        self.locality_label = ttk.Label(self, text="Locality:")
        self.organization_label = ttk.Label(self, text="Organization:")
        self.organization_input = ttk.Entry(self)
        self.organizational_unit_label = ttk.Label(self, text="Organizational Unit:")
        self.organizational_unit_input = ttk.Entry(self)
        self.create_certificate_signing_request_button = ttk.Button(self, text="Create Signing Request", command=self.create_certificate_signing_request)

        self.private_key_label.grid(row=0, column=0, pady=(0, 4), padx=(0, 2), sticky="e")
        self.private_key_input.grid(row=0, column=1, pady=(0, 4), padx=(2, 2), sticky="w")
        self.private_key_browse_button.grid(row=0, column=2, pady=(0, 4), padx=(2, 0))
        self.public_key_label.grid(row=1, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.public_key_input.grid(row=1, column=1, pady=(4, 4), padx=(2, 2), sticky="w")
        self.public_key_browse_button.grid(row=1, column=2, pady=(4, 4), padx=(2, 0))
        self.common_name_label.grid(row=2, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.common_name_input.grid(row=2, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.email_address_label.grid(row=3, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.email_address_input.grid(row=3, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.country_label.grid(row=4, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.country_input.grid(row=4, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.state_or_province_label.grid(row=5, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.state_or_province_input.grid(row=5, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.locality_label.grid(row=6, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.locality_input.grid(row=6, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.organization_label.grid(row=7, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.organization_input.grid(row=7, column=1, pady=(4, 4), padx=(2, 0), sticky="e")
        self.organizational_unit_label.grid(row=8, column=0, pady=(4, 4), padx=(0, 2), sticky="w")
        self.organizational_unit_input.grid(row=8, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.create_certificate_signing_request_button.grid(row=9, column=0, columnspan=2, pady=(4, 0), padx=(0, 0), sticky="we")

    def browse_private_key_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not filename:
            return
        self.private_key_input.config(state="normal")
        self.private_key_input.delete(0, "end")
        self.private_key_input.insert(0, filename)
        self.private_key_input.config(state="readonly")

    def browse_public_key_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not filename:
            return
        self.public_key_input.config(state="normal")
        self.public_key_input.delete(0, "end")
        self.public_key_input.insert(0, filename)
        self.public_key_input.config(state="readonly")

    def create_certificate_signing_request(self) -> None:
        try:
            certificate_signing_request = crypto.X509Req()

            private_key_file = open(self.private_key_input.get(), "rb")
            private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file.read())
            private_key_file.close()

            public_key_file = open(self.public_key_input.get(), "rb")
            public_key = crypto.load_publickey(crypto.FILETYPE_PEM, public_key_file.read())
            public_key_file.close()

            subject = certificate_signing_request.get_subject()
            if common_name := self.common_name_input.get(): subject.commonName = common_name
            if email_address := self.email_address_input.get(): subject.emailAddress = email_address
            if country := self.country_input.get(): subject.countryName = country
            if state_or_province := self.state_or_province_input.get(): subject.stateOrProvinceName = state_or_province
            if locality := self.locality_input.get(): subject.localityName = locality
            if organization := self.organization_input.get(): subject.organizationName = organization
            if organizational_unit := self.organizational_unit_input.get(): subject.organizationalUnitName = organizational_unit

            certificate_signing_request.set_pubkey(public_key)
            certificate_signing_request.sign(private_key, "sha256")

            certificate_signing_request_file = filedialog.asksaveasfile("wb", defaultextension=".csr", filetypes=[("Certificate Signing Request", "*.csr")])
            if certificate_signing_request_file is None:
                return
            certificate_signing_request_file.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, certificate_signing_request))
            certificate_signing_request_file.close()

            messagebox.showinfo("Create Certificate Signing Request", "Certificate Signing Request successfully created!")
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

class CreateCertificateFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=8)

        self.certificate_signing_request_label = ttk.Label(self, text="Certificate Signing Request")
        self.certificate_signing_request_input = ttk.Entry(self, state="readonly")
        self.certificate_signing_request_browse_button = ttk.Button(self, text="Browse", command=self.browse_certificate_signing_request_file)
        self.private_key_label = ttk.Label(self, text="Private Key:")
        self.private_key_input = ttk.Entry(self, state="readonly")
        self.private_key_browse_button = ttk.Button(self, text="Browse", command=self.browse_private_key_file)
        self.validity_days_label = ttk.Label(self, text="Validity days:")
        self.validity_days_input = ttk.Entry(self)
        self.create_certificate_button = ttk.Button(self, text="Create Certificate", command=self.create_certificate)

        self.certificate_signing_request_label.grid(row=0, column=0, pady=(0, 4), padx=(0, 2), sticky="e")
        self.certificate_signing_request_input.grid(row=0, column=1, pady=(0, 4), padx=(2, 2), sticky="w")
        self.certificate_signing_request_browse_button.grid(row=0, column=2, pady=(0, 4), padx=(2, 0))
        self.private_key_label.grid(row=1, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.private_key_input.grid(row=1, column=1, pady=(4, 4), padx=(2, 2), sticky="w")
        self.private_key_browse_button.grid(row=1, column=2, pady=(4, 4), padx=(2, 0))
        self.validity_days_label.grid(row=2, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.validity_days_input.grid(row=2, column=1, pady=(4, 4), padx=(2, 2), sticky="w")
        self.create_certificate_button.grid(row=3, column=0, columnspan=2, pady=(4, 0), padx=(0, 0), sticky="we")

    def browse_certificate_signing_request_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not filename:
            return
        self.certificate_signing_request_input.config(state="normal")
        self.certificate_signing_request_input.delete(0, "end")
        self.certificate_signing_request_input.insert(0, filename)
        self.certificate_signing_request_input.config(state="readonly")

    def browse_private_key_file(self) -> None:
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not filename:
            return
        self.private_key_input.config(state="normal")
        self.private_key_input.delete(0, "end")
        self.private_key_input.insert(0, filename)
        self.private_key_input.config(state="readonly")

    def create_certificate(self) -> None:
        try:
            certificate = crypto.X509()

            certificate_signing_request_file = open(self.certificate_signing_request_input.get(), "rb")
            certificate_signing_request = crypto.load_certificate_request(crypto.FILETYPE_PEM, certificate_signing_request_file.read())
            certificate_signing_request_file.close()

            private_key_file = open(self.private_key_input.get(), "rb")
            private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_file.read())
            private_key_file.close()

            validity_days = int(self.validity_days_input.get())

            certificate.set_subject(certificate_signing_request.get_subject())
            certificate.set_issuer(certificate_signing_request.get_subject())
            certificate.set_pubkey(certificate_signing_request.get_pubkey())
            certificate.gmtime_adj_notBefore(0)
            certificate.gmtime_adj_notAfter(validity_days * 24 * 60 * 60)
            certificate.sign(private_key, "sha256")

            certificate_file = filedialog.asksaveasfile("wb", defaultextension=".crt", filetypes=[("Certificate", "*.crt")])
            if certificate_file is None:
                return
            certificate_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
            certificate_file.close()

            messagebox.showinfo("Create Certificate", "Certificate successfully created!")
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

class ViewCertificateFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master, padding=8)

        self.certificate_file_label = ttk.Label(self, text="Certificate File:")
        self.certificate_file_input = ttk.Entry(self, state="readonly")
        self.certificate_file_browse_button = ttk.Button(self, text="Browse", command=self.read_certificate)
        self.certificate_url_label = ttk.Label(self, text="Certificate URL:")
        self.certificate_url_input = ttk.Entry(self)
        self.certificate_url_fetch_button = ttk.Button(self, text="Fetch", command=self.fetch_certificate)

        self.certificate_file_label.grid(row=0, column=0, pady=(0, 4), padx=(0, 2), sticky="e")
        self.certificate_file_input.grid(row=0, column=1, pady=(0, 4), padx=(2, 2), sticky="we")
        self.certificate_file_browse_button.grid(row=0, column=2, pady=(0, 4), padx=(2, 0))
        self.certificate_url_label.grid(row=1, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.certificate_url_input.grid(row=1, column=1, pady=(4, 4), padx=(2, 2), sticky="we")
        self.certificate_url_fetch_button.grid(row=1, column=2, pady=(4, 4), padx=(2, 0))

        self.separator1 = ttk.Separator(self, orient="horizontal")
        self.separator1.grid(row=2, column=0, columnspan=3, sticky="we")

        self.subject_common_name_label = ttk.Label(self, text="Common Name:")
        self.subject_common_name_value_label = ttk.Label(self)
        self.subject_email_address_label = ttk.Label(self, text="Email Address:")
        self.subject_email_address_value_label = ttk.Label(self)
        self.subject_country_label = ttk.Label(self, text="Country:")
        self.subject_country_value_label = ttk.Label(self)
        self.subject_locality_label = ttk.Label(self, text="Locality:")
        self.subject_locality_value_label = ttk.Label(self)
        self.subject_state_or_province_label = ttk.Label(self, text="State or Province:")
        self.subject_state_or_province_value_label = ttk.Label(self)
        self.subject_organization_label = ttk.Label(self, text="Organization:")
        self.subject_organization_value_label = ttk.Label(self)
        self.subject_organizational_unit_label = ttk.Label(self, text="Organizational Unit:")
        self.subject_organizational_unit_value_label = ttk.Label(self)

        self.subject_common_name_label.grid(row=3, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_common_name_value_label.grid(row=3, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.subject_email_address_label.grid(row=4, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_email_address_value_label.grid(row=4, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.subject_country_label.grid(row=5, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_country_value_label.grid(row=5, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.subject_state_or_province_label.grid(row=6, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_state_or_province_value_label.grid(row=6, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.subject_locality_label.grid(row=7, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_locality_value_label.grid(row=7, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.subject_organization_label.grid(row=8, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_organization_value_label.grid(row=8, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.subject_organizational_unit_label.grid(row=9, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.subject_organizational_unit_value_label.grid(row=9, column=1, pady=(4, 4), padx=(2, 0), sticky="w")

        self.separator2 = ttk.Separator(self, orient="horizontal")
        self.separator2.grid(row=10, column=0, columnspan=3, sticky="we")

        self.issuer_common_name_label = ttk.Label(self, text="Common Name:")
        self.issuer_common_name_value_label = ttk.Label(self)
        self.issuer_email_address_label = ttk.Label(self, text="Email Address:")
        self.issuer_email_address_value_label = ttk.Label(self)
        self.issuer_country_label = ttk.Label(self, text="Country:")
        self.issuer_country_value_label = ttk.Label(self)
        self.issuer_state_or_province_label = ttk.Label(self, text="State or Province:")
        self.issuer_state_or_province_value_label = ttk.Label(self)
        self.issuer_locality_value_label = ttk.Label(self)
        self.issuer_locality_label = ttk.Label(self, text="Locality:")
        self.issuer_organization_label = ttk.Label(self, text="Organization:")
        self.issuer_organization_value_label = ttk.Label(self)
        self.issuer_organizational_unit_label = ttk.Label(self, text="Organizational Unit:")
        self.issuer_organizational_unit_value_label = ttk.Label(self)

        self.issuer_common_name_label.grid(row=11, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_common_name_value_label.grid(row=11, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.issuer_email_address_label.grid(row=12, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_email_address_value_label.grid(row=12, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.issuer_country_label.grid(row=13, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_country_value_label.grid(row=13, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.issuer_state_or_province_label.grid(row=14, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_state_or_province_value_label.grid(row=14, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.issuer_locality_label.grid(row=15, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_locality_value_label.grid(row=15, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.issuer_organization_label.grid(row=16, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_organization_value_label.grid(row=16, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.issuer_organizational_unit_label.grid(row=17, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.issuer_organizational_unit_value_label.grid(row=17, column=1, pady=(4, 0), padx=(2, 0), sticky="w")

        self.separator3 = ttk.Separator(self, orient="horizontal")
        self.separator3.grid(row=18, column=0, columnspan=3, sticky="we")

        self.validity_not_before_label = ttk.Label(self, text="Not Before:")
        self.validity_not_before_value_label = ttk.Label(self)
        self.validity_not_after_label = ttk.Label(self, text="Not After:")
        self.validity_not_after_value_label = ttk.Label(self)

        self.validity_not_before_label.grid(row=19, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.validity_not_before_value_label.grid(row=19, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.validity_not_after_label.grid(row=20, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.validity_not_after_value_label.grid(row=20, column=1, pady=(4, 4), padx=(2, 0), sticky="w")

        self.separator4 = ttk.Separator(self, orient="horizontal")
        self.separator4.grid(row=21, column=0, columnspan=3, sticky="we")

        self.public_key_algorithm_label = ttk.Label(self, text="Algorithm:")
        self.public_key_algorithm_value_label = ttk.Label(self)
        self.public_key_size_label = ttk.Label(self, text="Key Size:")
        self.public_key_size_value_label = ttk.Label(self)

        self.public_key_algorithm_label.grid(row=22, column=0, pady=(4, 4), padx=(0, 2), sticky="e")
        self.public_key_algorithm_value_label.grid(row=22, column=1, pady=(4, 4), padx=(2, 0), sticky="w")
        self.public_key_size_label.grid(row=23, column=0, pady=(4, 0), padx=(0, 2), sticky="e")
        self.public_key_size_value_label.grid(row=23, column=1, pady=(4, 0), padx=(2, 0), sticky="w")

    def read_certificate(self) -> None:
        try:
            certificate_file = filedialog.askopenfile("rb", filetypes=[("All Files", "*.*")])
            if not certificate_file:
                return
            self.certificate_url_input.delete(0, "end")
            self.certificate_file_input.config(state="normal")
            self.certificate_file_input.delete(0, "end")
            self.certificate_file_input.insert(0, certificate_file.name)
            self.certificate_file_input.config(state="readonly")
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_file.read())
            certificate_file.close()
            self._display_certificate(certificate)
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

    def fetch_certificate(self) -> None:
        try:
            certificate_url_hostname = self.certificate_url_input.get()
            if not certificate_url_hostname:
                return

            self.certificate_file_input.config(state="normal")
            self.certificate_file_input.delete(0, "end")
            self.certificate_file_input.config(state="readonly")
            certificate_url_port = 443
            certificate_url = (certificate_url_hostname, certificate_url_port)
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, ssl.get_server_certificate(certificate_url).encode())
            self._display_certificate(certificate)
        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

    def _display_certificate(self, certificate: crypto.X509) -> None:
        subject = certificate.get_subject()
        self.subject_common_name_value_label.config(text=subject.commonName)
        self.subject_email_address_value_label.config(text=subject.emailAddress)
        self.subject_country_value_label.config(text=subject.countryName)
        self.subject_state_or_province_value_label.config(text=subject.stateOrProvinceName)
        self.subject_locality_value_label.config(text=subject.localityName)
        self.subject_organization_value_label.config(text=subject.organizationName)
        self.subject_organizational_unit_value_label.config(text=subject.organizationalUnitName)

        issuer = certificate.get_issuer()
        self.issuer_common_name_value_label.config(text=issuer.commonName)
        self.issuer_email_address_value_label.config(text=issuer.emailAddress)
        self.issuer_country_value_label.config(text=issuer.countryName)
        self.issuer_state_or_province_value_label.config(text=issuer.stateOrProvinceName)
        self.issuer_locality_value_label.config(text=issuer.localityName)
        self.issuer_organization_value_label.config(text=issuer.organizationName)
        self.issuer_organizational_unit_value_label.config(text=issuer.organizationalUnitName)

        self.validity_not_before_value_label.config(text=certificate.get_notBefore().decode())
        self.validity_not_after_value_label.config(text=certificate.get_notAfter().decode())

        public_key = certificate.get_pubkey()
        self.public_key_algorithm_value_label.config(text="RSA")
        self.public_key_size_value_label.config(text=public_key.bits())
