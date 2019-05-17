#!/bin/bash

KEYFILE="privkey.pem";
CERTFILE="certificate.pem";
PUBKEYFILE="pubkey.pem";
NMOSAUTH_DIR="/var/nmosauth"
subinfo='/C=UK/L=London/O=Example/CN=www.example.co.uk';

[ -e $CERTFILE ] && rm $CERTFILE;
[ -e $KEYFILE ] && rm $KEYFILE;
[ -e $PUBKEYFILE ] && rm $PUBKEYFILE;

openssl req -newkey rsa:2048 -nodes -subj "$subinfo" -keyout $KEYFILE -x509 -days 365 -outform PEM -out $CERTFILE > /dev/null 2>&1;
openssl x509 -in $CERTFILE -noout -pubkey > $PUBKEYFILE

chown ipstudio:ipstudio $KEYFILE
chown ipstudio:ipstudio $PUBKEYFILE
chown ipstudio:ipstudio $CERTFILE

chmod 600 $KEYFILE
chmod 600 $PUBKEYFILE
chmod 600 $CERTFILE
chmod 700 -- "$0"

mv $KEYFILE $NMOSAUTH_DIR
mv $CERTFILE $NMOSAUTH_DIR
mv $PUBKEYFILE $NMOSAUTH_DIR
