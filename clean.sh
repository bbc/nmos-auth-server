#!/bin/sh
sudo rm -rf /usr/local/lib/python2.7/dist-packages/nmosauth
sudo rm -rf /usr/local/lib/python2.7/dist-packages/nmos_auth-0.0.0.egg-info
sudo rm -rf /usr/lib/python2.7/dist-packages/nmosauth
sudo rm -rf /var/nmosauth
sudo rm -f /usr/bin/nmosauth
sudo rm -f /lib/systemd/system/python-auth.service
