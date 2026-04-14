#!/bin/bash

echo "[+] Checking DNS"
dig +short meta.com

echo "[+] Checking subdomain"
dig +short auth.meta.com

echo "[+] Checking buckets"
for b in meta-assets meta-static meta-api; do
  echo "---- $b ----"
  curl -s https://storage.googleapis.com/$b/ | head -n 5
done

echo "[+] Checking origin claim"
curl -H "Host: meta.com" http://167.71.204.56 -m 5

