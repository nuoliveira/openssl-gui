from OpenSSL import crypto, SSL

def main():
    print("Hello, world!")

def view_certificate_example():
    pass

def create_certificate_example():
    pass

def create_keypair_example():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    open("teste.key", "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open("teste.pem", "wb").write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))

def encrypt_file_example():
    key = crypto.PKey()
    pass

def decrypt_file_example():
    pass

def verify_file_integrity_example():
    pass

if __name__ == '__main__':
    main()
