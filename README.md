# cs-security-comps-2026

This repository contains our 2026 CS Security Comps project.

Authors: Rachel Azan, Jeremy Gautama, Palmy Klangsathorn, Daniel Lumbu

## Do SSH into the AWS EC2 Server

Set the correct permissions for the private key file using the chmod command (SSH requires the key to be unreadable by others):
bash
`chmod 400 CompsServerKey.pem`
Connect to your instance using the ssh command:
bash
`ssh -i "CompsServerKey.pem" ubuntu@18.191.221.152`

change the username@ipaddress to your username and ip address!
