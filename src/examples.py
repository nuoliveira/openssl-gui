from OpenSSL import crypto
from ssl import get_server_certificate

def main() -> None:
    # verify_file_integrity_example()
    create_keypair_example()
    encrypt_file_example()
    # decrypt_file_example()
    # create_certificate_signing_request_example()
    # create_certificate_example()
    # view_certificate_from_file_example()
    # view_certificate_from_url_example()

def verify_file_integrity_example() -> None:
    file_path = "assets/example.txt"

def create_keypair_example() -> None:
    public_key_file_path = "assets/public.pub"
    private_key_file_path = "assets/private.key"
    key_pair_type = crypto.TYPE_RSA
    key_pair_size = 512
    key_pair = crypto.PKey()
    key_pair.generate_key(key_pair_type, key_pair_size)
    with open(public_key_file_path, "wb") as public_key_file:
        public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key_pair))
    with open(private_key_file_path, "wb") as private_key_file:
        private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))

def encrypt_file_example() -> None:
    input_file_path = "assets/encrypt.txt"
    output_file_path = "assets/encrypt.txt.enc"
    encryption_key_file_path = "assets/public.pub"
    encryption_key_type = crypto.TYPE_RSA
    with open(encryption_key_file_path, "rb") as public_key_file:
        encryption_key = crypto.load_publickey(encryption_key_type, public_key_file.read()).to_cryptography_key()
    with open(input_file_path, "rb") as input_file:
        input_file_contents = input_file.read()
    with open(output_file_path, "wb") as output_file:
        output_file.write(encryption_key.encrypt(input_file_contents, ...))

def decrypt_file_example() -> None:
    input_file_path = "assets/decrypt.txt.enc"
    output_file_path = "assets/decrypt.txt"
    decryption_key_file_path = "assets/private.key"
    decryption_key_type = crypto.TYPE_RSA
    with open(decryption_key_file_path, "rt") as public_key_file:
        decryption_key = crypto.load_privatekey(decryption_key_type, public_key_file.read()).to_cryptography_key()
    with open(input_file_path, "rt") as input_file:
        input_file_contents = input_file.read()
    with open(output_file_path) as output_file:
        output_file.write(decryption_key.decrypt(input_file_contents, ...))


def view_certificate_from_file_example() -> None:
    certificate_file_path = "assets/ipvc.crt"
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate_file_path, "rb").read())
    print_certificate(certificate)

def view_certificate_from_url_example() -> None:
    certificate_url_hostname = "www.ipvc.pt"
    certificate_url_port = 443
    certificate_url = (certificate_url_hostname, certificate_url_port)
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, get_server_certificate(certificate_url).encode())
    print_certificate(certificate)

def print_certificate(certificate: crypto.X509) -> None:
    subject = certificate.get_subject()
    print("Subject:")
    print("- Common Name:", subject.commonName)
    print("- Email Address:", subject.emailAddress)
    print("- Country:", subject.countryName)
    print("- State or Province:", subject.stateOrProvinceName)
    print("- Locality:", subject.localityName)
    print("- Organization:", subject.organizationName)
    print("- Organization Unit:", subject.organizationalUnitName)

    print()

    issuer = certificate.get_issuer()
    print("Issuer:")
    print("- Common Name:", issuer.commonName)
    print("- Email Address:", issuer.emailAddress)
    print("- Country:", issuer.countryName)
    print("- State or Province:", issuer.stateOrProvinceName)
    print("- Locality:", issuer.localityName)
    print("- Organization:", issuer.organizationName)
    print("- Organization Unit:", issuer.organizationalUnitName)

    print()

    public_key = certificate.get_pubkey()
    print("Public Key:")
    print("- Key Type", public_key.type())
    print("- Key Size", public_key.bits())

    print()

    print("Validity:")
    print("- Not Before:", certificate.get_notBefore())
    print("- Not After:", certificate.get_notAfter())

if __name__ == '__main__':
    main()
