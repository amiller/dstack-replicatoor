set -x

REPL_FROM=172.25.0.2:4001
REPL_TO=127.0.0.1:4001

# Request the key
curl -s -X POST http://$REPL_TO/requestKey > request.out
PUBK=$(cat request.out | jq -r .pubk)
QUOTE=$(cat request.out | jq -r .quote)

# Prepare the encrypted state file
curl -s -X POST -d "pubk=$PUBK" -d "quote=$QUOTE"  http://$REPL_FROM/onboard > onboard.out

# Load the encrypted state file
curl -X POST -H "Content-Type: text/plain" --data-binary @onboard.out http://$REPL_TO/receiveKey
curl http://$REPL_TO/status

