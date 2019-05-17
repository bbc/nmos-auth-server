#!/usr/bin/python

from OpenSSL import crypto
import os

from nmosauth.auth_server.constants import CERT_PATH, PRIVKEY_PATH


def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "Dummy Company Ltd"  # noqa: E741
    cert.get_subject().OU = "Dummy Company Ltd"
    cert.get_subject().CN = "www.example.com"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, b'sha256')

    # Write Cert and Private Key to File
    open(CERT_PATH, "wt").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(PRIVKEY_PATH, "wt").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

    # Change permissions to Read-Only for security
    os.chmod(CERT_PATH, 0o400)
    os.chmod(PRIVKEY_PATH, 0o400)


create_self_signed_cert()
