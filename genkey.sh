#!/bin/bash
rm -r keys/*
openssl genrsa -out keys/ca_key.pem 2048;
for i in `seq 1 10`; do
    openssl genrsa -out keys/${i}_key.pem 2048;
done;