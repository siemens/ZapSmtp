#!/bin/bash

openssl req -newkey rsa:4096 -nodes -keyout key.pem -x509 -days 3650 -outform pem -out cert.pem
