#!/bin/bash

# Generate new self-signed certificate
openssl req -new -x509 -days 365 -nodes -out certchain.pem -keyout private.key
