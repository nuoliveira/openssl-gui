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
        self.input_file_frame = ttk.Labelframe(self, text="Input")

        self.input_file_label = ttk.Label(self.input_file_frame, text="File")
        self.input_file_label.pack()
        self.input_file_input = ttk.Entry(self.input_file_frame, state="readonly")
        self.input_file_input.pack()
        self.input_file_browse_button = ttk.Button(self.input_file_frame, text="Browse", command=self._browse_input_file)
        self.input_file_browse_button.pack()

        self.hash_algorithm_input = ttk.Combobox(self.input_file_frame, values=tuple(hashlib.algorithms_available), state="readonly")
        self.hash_algorithm_input.pack()

        self.verify_file_button = ttk.Button(self.input_file_frame, text="Verify", command=self._verify_file_integrity)
        self.verify_file_button.pack()

        self.input_file_frame.pack()

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
        self.public_key_label = ttk.Label(self, text="Public Key")
        self.public_key_label.pack()
        self.public_key_input = ttk.Entry(self, state="readonly")
        self.public_key_input.pack()
        self.public_key_browse_button = ttk.Button(self, text="Browse", command=self._browse_public_key)
        self.public_key_browse_button.pack()

        self.private_key_label = ttk.Label(self, text="Private Key")
        self.private_key_label.pack()
        self.private_key_input = ttk.Entry(self, state="disabled")
        self.private_key_input.pack()
        self.private_key_browse_button = ttk.Button(self, text="Browse", command=self._browse_private_key)
        self.private_key_browse_button.pack()

        self.key_pair_type_label = ttk.Label(self, text="Key Pair Type")
        self.key_pair_type_label.pack()
        self.key_pair_type_input = ttk.Combobox(self, values=("RSA", "DSA"), state="readonly")
        self.key_pair_type_input.pack()

        self.key_pair_size_label = ttk.Label(self, text="Key Pair Size")
        self.key_pair_size_label.pack()
        self.key_pair_size_input = ttk.Combobox(self, values=("512", "1024", "2048", "4096"), state="readonly")
        self.key_pair_size_input.pack()

        self.key_pair_create_button = ttk.Button(self, text="Create Key Pair", command=self._create_keypair)
        self.key_pair_create_button.pack()

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
            key_pair_size = self.key_pair_size_input.get()

            key_pair = crypto.PKey()
            key_pair.generate_key(key_pair_type, key_pair_size)

            with open(public_key_file_path, "wb") as public_key_file:
                public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair))
            with open(private_key_file_path, "wb") as private_key_file:
                private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))

        except Exception as exception:
            messagebox.showerror("Error", "".join(traceback.format_exception(exception)))

class ViewCertificateFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)

        self.certificate_frame = ttk.Labelframe(self, text="Certificate")
        self.certificate_label = ttk.Label(self, text="Certificate")
        self.certificate_file_input = ttk.Entry(self, state="readonly")
        self.certificate_browse_button = ttk.Button(self, text="Browse", command=self._browse_certificate)

        self.certificate_label.grid(row=0, column=0)
        self.certificate_file_input.grid(row=0, column=1)
        self.certificate_browse_button.grid(row=0, column=2)


        self.subject_frame = ttk.LabelFrame(self, text="Subject")

        self.subject_common_name_label = ttk.Label(self.subject_frame, text="Common Name")
        self.subject_common_name_value_label = ttk.Label(self.subject_frame)
        self.subject_email_address_label = ttk.Label(self.subject_frame, text="Email Address")
        self.subject_email_address_value_label = ttk.Label(self.subject_frame)
        self.subject_country_label = ttk.Label(self.subject_frame, text="Country")
        self.subject_country_value_label = ttk.Label(self.subject_frame)
        self.subject_locality_label = ttk.Label(self.subject_frame, text="Locality")
        self.subject_locality_value_label = ttk.Label(self.subject_frame)
        self.subject_state_or_province_label = ttk.Label(self.subject_frame, text="State or Province")
        self.subject_state_or_province_value_label = ttk.Label(self.subject_frame)
        self.subject_organization_label = ttk.Label(self.subject_frame, text="Organization")
        self.subject_organization_value_label = ttk.Label(self.subject_frame)
        self.subject_organization_unit_label = ttk.Label(self.subject_frame, text="Organization Unit")
        self.subject_organization_unit_value_label = ttk.Label(self.subject_frame)

        self.subject_common_name_label.grid(row=1, column=0)
        self.subject_common_name_value_label.grid(row=1, column=1)
        self.subject_email_address_label.grid(row=2, column=0)
        self.subject_email_address_value_label.grid(row=2, column=1)
        self.subject_country_label.grid(row=3, column=0)
        self.subject_country_value_label.grid(row=3, column=1)
        self.subject_state_or_province_label.grid(row=4, column=0)
        self.subject_state_or_province_value_label.grid(row=4, column=1)
        self.subject_locality_label.grid(row=5, column=0)
        self.subject_locality_value_label.grid(row=5, column=1)
        self.subject_organization_label.grid(row=6, column=0)
        self.subject_organization_value_label.grid(row=6, column=1)
        self.subject_organization_unit_value_label.grid(row=7, column=1)
        self.subject_organization_unit_label.grid(row=7, column=0)

        self.subject_frame.grid(row=1, column=0)


        self.issuer_frame = ttk.LabelFrame(self, text="Issuer")

        self.issuer_common_name_label = ttk.Label(self.issuer_frame, text="Common Name")
        self.issuer_common_name_value_label = ttk.Label(self.issuer_frame)
        self.issuer_email_address_label = ttk.Label(self.issuer_frame, text="Email Address")
        self.issuer_email_address_value_label = ttk.Label(self.issuer_frame)
        self.issuer_country_label = ttk.Label(self.issuer_frame, text="Country")
        self.issuer_country_value_label = ttk.Label(self.issuer_frame)
        self.issuer_locality_label = ttk.Label(self.issuer_frame, text="Locality")
        self.issuer_locality_value_label = ttk.Label(self.issuer_frame)
        self.issuer_state_or_province_label = ttk.Label(self.issuer_frame, text="State or Province")
        self.issuer_state_or_province_value_label = ttk.Label(self.issuer_frame)
        self.issuer_organization_label = ttk.Label(self.issuer_frame, text="Organization")
        self.issuer_organization_value_label = ttk.Label(self.issuer_frame)
        self.issuer_organization_unit_label = ttk.Label(self.issuer_frame, text="Organization Unit")
        self.issuer_organization_unit_value_label = ttk.Label(self.issuer_frame)

        self.issuer_common_name_label.grid(row=0, column=0)
        self.issuer_common_name_value_label.grid(row=0, column=1)
        self.issuer_email_address_label.grid(row=1, column=0)
        self.issuer_email_address_value_label.grid(row=1, column=1)
        self.issuer_country_label.grid(row=2, column=0)
        self.issuer_country_value_label.grid(row=2, column=1)
        self.issuer_state_or_province_label.grid(row=3, column=0)
        self.issuer_state_or_province_value_label.grid(row=3, column=1)
        self.issuer_locality_label.grid(row=4, column=0)
        self.issuer_locality_value_label.grid(row=4, column=1)
        self.issuer_organization_label.grid(row=5, column=0)
        self.issuer_organization_value_label.grid(row=5, column=1)
        self.issuer_organization_unit_label.grid(row=6, column=0)
        self.issuer_organization_unit_value_label.grid(row=6, column=1)

        self.issuer_frame.grid(row=2, column=0)

        self.validity_frame = ttk.LabelFrame(self, text="Validity")

        self.validity_not_before_label = ttk.Label(self.validity_frame, text="Not Before")
        self.validity_not_before_value_label = ttk.Label(self.validity_frame)
        self.validity_not_after_label = ttk.Label(self.validity_frame, text="Not After")
        self.validity_not_after_value_label = ttk.Label(self.validity_frame)

        self.validity_not_before_label.grid(row=15, column=0)
        self.validity_not_before_value_label.grid(row=15, column=1)
        self.validity_not_after_label.grid(row=16, column=0)
        self.validity_not_after_value_label.grid(row=16, column=1)

        self.validity_frame.grid(row=3, column=0)


        self.public_key_frame = ttk.LabelFrame(self, text="Public Key")

        self.public_key_algorithm_label = ttk.Label(self.public_key_frame, text="Algorithm")
        self.public_key_algorithm_value_label = ttk.Label(self.public_key_frame)
        self.public_key_size_label = ttk.Label(self.public_key_frame, text="Key Size")
        self.public_key_size_value_label = ttk.Label(self.public_key_frame)

        self.public_key_algorithm_label.grid(row=17, column=0)
        self.public_key_algorithm_value_label.grid(row=17, column=1)
        self.public_key_size_label.grid(row=18, column=0)
        self.public_key_size_value_label.grid(row=18, column=1)

        self.public_key_frame.grid(row=4, column=0)

        # self.issuer_frame = ttk.LabelFrame(self, text="Issuer")
        # self.issuer_frame.pack()

        # self.validity_frame = ttk.LabelFrame(self, text="Validity")
        # self.validity_frame.pack()

        # self.key_frame = ttk.LabelFrame(self, text="Key")
        # self.key_frame.pack()

    def _browse_certificate(self) -> None:
        certificate_file = filedialog.askopenfile("rb", filetypes=[("All Files", "*.*")])
        if not certificate_file:
            return

        self.certificate_file_input.config(state="normal")
        self.certificate_file_input.delete(0, "end")
        self.certificate_file_input.insert(0, certificate_file.name)
        self.certificate_file_input.config(state="readonly")

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_file.read())

        subject = certificate.get_subject()
        self.subject_common_name_value_label.config(text=subject.commonName)
        self.subject_email_address_value_label.config(text=subject.emailAddress)
        self.subject_country_value_label.config(text=subject.countryName)
        self.subject_state_or_province_value_label.config(text=subject.stateOrProvinceName)
        self.subject_locality_value_label.config(text=subject.localityName)
        self.subject_organization_value_label.config(text=subject.organizationName)
        self.subject_organization_unit_value_label.config(text=subject.organizationalUnitName)

        issuer = certificate.get_issuer()
        self.issuer_common_name_value_label.config(text=issuer.commonName)
        self.issuer_email_address_value_label.config(text=issuer.emailAddress)
        self.issuer_country_value_label.config(text=issuer.countryName)
        self.issuer_state_or_province_value_label.config(text=issuer.stateOrProvinceName)
        self.issuer_locality_value_label.config(text=issuer.localityName)
        self.issuer_organization_value_label.config(text=issuer.organizationName)
        self.issuer_organization_unit_value_label.config(text=issuer.organizationalUnitName)

        self.validity_not_before_value_label.config(text=certificate.get_notBefore().decode())
        self.validity_not_after_value_label.config(text=certificate.get_notAfter().decode())

        public_key = certificate.get_pubkey()
        self.public_key_algorithm_value_label.config(text=public_key.type())
        self.public_key_size_value_label.config(text=public_key.bits())

        certificate_file.close()

class CreateCertificateFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)

class CreateCertificateSigningRequestFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)

# class EncryptFileFrame(ttk.Frame):
#     def __init__(self, master: tk.Misc) -> None:
#         super().__init__(master)

# class DecryptFileFrame(ttk.Frame):
#     def __init__(self, master: tk.Misc) -> None:
#         super().__init__(master)
