# Check if both GUEST_FROM and GUEST_TO arguments are provided
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: Both GUEST_FROM and GUEST_2 must be provided."
    echo "Usage: $0 GUEST_FROM GUEST_TO"
    exit 1
fi

# Assign command line arguments to variables
GUEST_FROM=$1
GUEST_TO=$2

# Request the key
curl -s -X POST http://$GUEST_TO/requestKey > request.out
PUBK=$(cat request.out | jq -r .pubk)
QUOTE=$(cat request.out | jq -r .quote)

# Prepare the encrypted state file
curl -s -X POST -d "pubk=$PUBK" -d "quote=$QUOTE"  http://$GUEST_FROM/onboard > onboard.out

# Load the encrypted state file
curl -X POST -H "Content-Type: text/plain" --data-binary @onboard.out http://$GUEST_TO/receiveKey
curl http://$GUEST_TO/status

