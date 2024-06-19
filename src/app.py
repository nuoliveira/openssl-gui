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

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_file.read())
        self._update_certificate_info(certificate)
        certificate_file.close()

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
        pass  # Add widgets for creating certificates


class CreateCertificateSigningRequestFrame(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self) -> None:
        pass  # Add widgets for creating certificate signing requests


if __name__ == "__main__":
    app = App()
    app.run()
