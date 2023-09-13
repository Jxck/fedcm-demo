#!/bin/sh

cd cert
\rm *.pem
mkcert idp.example
mkcert rp.example
