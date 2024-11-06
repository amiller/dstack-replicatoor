#!/bin/bash

set -e
set -x

# Run the go server for verification locally
dcap-verifier --listen-addr 127.0.0.1:8001 &
VERIFIER_SERVER=$!

# Run the python server
python3 replicatoor.py

