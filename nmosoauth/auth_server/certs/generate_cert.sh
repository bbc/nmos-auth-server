#!/bin/bash

# ssh-keygen -t rsa -b 2048 -f jwtRS256.key -N ''
# # Don't add passphrase
# openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub

KEYFILE="privkey.pem";
CERTFILE="certificate.pem";
PUBKEYFILE="pubkey.pem";
subinfo='/C=UK/L=Manchester/O=BBC/CN=www.bbc.co.uk';

[ -e $CERTFILE ] && rm $CERTFILE;
[ -e $KEYFILE ] && rm $KEYFILE;
[ -e $PUBKEYFILE ] && rm $PUBKEYFILE;

openssl req -newkey rsa:2048 -nodes -subj "$subinfo" -keyout $KEYFILE -x509 -days 365 -outform PEM -out $CERTFILE;
openssl x509 -in $CERTFILE -noout -pubkey > $PUBKEYFILE

chown ipstudio:ipstudio $KEYFILE
chown ipstudio:ipstudio $PUBKEYFILE
chown ipstudio:ipstudio $CERTFILE

mv $KEYFILE /var/nmosoauth
mv $CERTFILE /var/nmosoauth
mv $PUBKEYFILE /var/nmosoauth
