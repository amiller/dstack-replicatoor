#!/bin/bash

# Configure to the IP address of the container
GUEST=172.20.0.2:4001

set -x
set -e
curl http://$GUEST/status
curl -X POST http://$GUEST/bootstrap
curl -X POST http://$GUEST/bootstrap # fails second time
curl http://$GUEST/status
