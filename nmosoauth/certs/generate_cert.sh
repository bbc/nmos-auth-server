#!/bin/bash

KEYFILE="privkey.pem";
CERTFILE="certificate.pem";
PUBKEYFILE="pubkey.pem";
NMOSOAUTH_DIR="/var/nmosoauth"
subinfo='/C=UK/L=Manchester/O=BBC/CN=www.bbc.co.uk';

[ -e $CERTFILE ] && rm $CERTFILE;
[ -e $KEYFILE ] && rm $KEYFILE;
[ -e $PUBKEYFILE ] && rm $PUBKEYFILE;

openssl req -newkey rsa:2048 -nodes -subj "$subinfo" -keyout $KEYFILE -x509 -days 365 -outform PEM -out $CERTFILE;
openssl x509 -in $CERTFILE -noout -pubkey > $PUBKEYFILE

chown ipstudio:ipstudio $KEYFILE
chown ipstudio:ipstudio $PUBKEYFILE
chown ipstudio:ipstudio $CERTFILE

mv $KEYFILE $NMOSOAUTH_DIR
mv $CERTFILE $NMOSOAUTH_DIR
mv $PUBKEYFILE $NMOSOAUTH_DIR
