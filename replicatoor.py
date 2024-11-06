from flask import Flask, jsonify, request
from nacl.public import PrivateKey, SealedBox, PublicKey
import subprocess
import requests
import requests_unixsocket
import os
import hashlib
from eth_account import Account
from eth_account.messages import encode_defunct
import time
import json
import sys
import base64
import re

# Untrusted environment values
ETH_API_KEY     = None
ETH_RPC_URL     = None

# Trusted values read from image
ETH_RPC_BASE = os.environ['ETH_RPC_URL']
CONTRACT    = os.environ['CONTRACT']
CHAIN_ID    = os.environ['CHAIN_ID']

# Here's all the key state
global_state = dict(
    myKey = None,
    xPriv = None,
    addr = None,
    bootstrap_quote = None,
    onboard_quote = None,
)

app = Flask(__name__)

def get_dstack_quote(appdata):
    session = requests_unixsocket.Session()
    return session.post('http+unix://%2Fvar%2Frun%2Ftappd.sock/prpc/Tappd.TdxQuote?json', data=appdata)

# To get a quote
def get_quote(appdata):
    # Try to use the dstack tappd
    try:
        quote = get_dstack_quote(appdata)
        return quote
    except requests.exceptions.ConnectionError:
        # Fetch a dummy quote
        cmd = f"curl -sk http://ns31695324.ip-141-94-163.eu:10080/attest/{appdata} --output - | od -An -v -tx1 | tr -d ' \n'"
        return subprocess.check_output(cmd, shell=True).decode('utf-8')

def extend_report_data(tag, report_data):
    # Recompute the appdata we're expecting
    s = tag.encode('utf-8') + b":" + bytes.fromhex(report_data)
    print('appdata preimage:', s)
    appdata = hashlib.sha256(s).hexdigest()
    report_data[:32] == appdata
    
# Verifies the signatures of a quote and returns
# it in a parsed form for further authorization checks
def verify_quote(quote):
    # See run.sh, go run cmd/httpserver/main.go
    url = 'http://localhost:8001/verify'
    resp = requests.post(url, data=bytes.fromhex(quote))

    # Parse out the relevant details
    obj = resp.json()
    header_user_data = base64.b64decode(obj['header']['user_data']).hex()
    report_data = base64.b64decode(obj['td_quote_body']['report_data']).hex()
    mrtd = base64.b64decode(obj['td_quote_body']['mr_td']).hex()
    rtmr0 = base64.b64decode(obj['td_quote_body']['rtmrs'][0]).hex()
    rtmr1 = base64.b64decode(obj['td_quote_body']['rtmrs'][1]).hex()
    rtmr2 = base64.b64decode(obj['td_quote_body']['rtmrs'][2]).hex()
    rtmr3 = base64.b64decode(obj['td_quote_body']['rtmrs'][3]).hex()
    chain = obj['signed_data']['certification_data']['qe_report_certification_data']['pck_certificate_chain_data']['pck_cert_chain']
    FMSPC = extract_fmspc(chain)
    obj['report_data'] = report_data
    obj['fmspc'] = FMSPC
    obj['rtmr0'] = rtmr0
    obj['rtmr1'] = rtmr1
    obj['rtmr2'] = rtmr2
    obj['rtmr3'] = rtmr3
    obj['mrtd'] = mrtd    
    return obj


def extract_fmspc(chain):
    d = base64.b64decode(chain).decode('utf-8')
    first = d.split('-----END CERTIFICATE-----')[0] +\
        '-----END CERTIFICATE-----'
    out = subprocess.check_output('openssl x509 -outform DER -out tmp.der', input=first.encode('utf-8'), shell=True)
    proc = subprocess.Popen('dumpasn1 tmp.der', stdin=None, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, text=True)
    for line in proc.stdout:
        if "OBJECT IDENTIFIER '1 2 840 113741 1 13 1 4'" in line:
            octet_line = next(proc.stdout)
            # Extract hex bytes using regex
            match = re.search(r'OCTET STRING\s+([A-F0-9 ]+)', octet_line)
            if match:
                hex_value = match.group(1).replace(' ', '')
                break
    return hex_value


def is_bootstrapped():
    cmd = f"cast call {CONTRACT} 'xPub()'"
    out = subprocess.check_output(cmd, shell=True).decode('utf-8')
    return out.strip() != "0x"+"0"*64

def check_mrtd(mrtd, rtmr0, rtmr3):
    cmd = f"cast call {CONTRACT} 'get_mrtd(bytes,bytes,bytes)(bool)' {mrtd0} {rtmr0} {rtmr3}"
    out = subprocess.check_output(cmd, shell=True).decode('utf-8')
    return out.strip() != "0x"+"0"*64

#####################
# Host interface 
#####################
# Called by the host if it's important to bootstrap

# Pass API keys and other arguments from the host
@app.route('/configure', methods=['POST'])
def configure():
    env_data = request.data.decode('utf-8')
    config = {}

    for line in env_data.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            config[key.strip()] = value.strip()
    print('Received configuration parameters:', config)
    global ETH_API_KEY
    global ETH_RPC_URL
    ETH_API_KEY = config['ETH_API_KEY']
    ETH_RPC_URL = ETH_RPC_BASE + config['ETH_API_KEY']
    return jsonify({"status": "success", "config": config}), 200

# Create a fresh key
@app.route('/bootstrap', methods=['POST'])
def bootstrap():
    global global_state
    if global_state['xPriv']:
        print('Already have xPriv, not replacing')
        return 'Already have xPriv, not replacing', 300
    print('Generating a fresh key', file=sys.stderr)

    # Generate the random key
    xPriv = os.urandom(32)
    addr = Account.from_key(xPriv).address

    # Get the quote
    appdata = hashlib.sha256(b"boostrap:" + addr.encode('utf-8')).hexdigest()
    quote = get_quote(appdata)

    # Print the parsed quote
    obj = verify_quote(quote)
    print(obj)

    # Store the quote for the host later (redundant)
    global_state['addr'] = addr
    global_state['xPriv'] = xPriv.hex()
    global_state['bootstrap_quote'] = quote
    
    # Ask the host service to post the tx, return when done
    return dict(addr=addr, quote=quote)

# Request a copy of existing key
@app.route('/requestKey', methods=['POST'])
def requestKey():
    print('Requesting the key...', file=sys.stderr)

    # Generate a private key and a corresponding public key
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    print('public_key:', bytes(public_key).hex(), file=sys.stderr)

    # Generate a private key and corresponding address
    myPriv = os.urandom(32)

    # Get the quote
    s = b"register:" + bytes(public_key)
    appdata = hashlib.sha256(b"register:" + bytes(public_key)).hexdigest()
    quote = get_quote(appdata)

    # Store the quote for the host later
    global_state['myPriv'] = bytes(private_key)
    global_state['myPub']  = bytes(public_key)
    global_state['onboard_quote'] = quote


#####################
# Receive the key
#####################
# Invoked by dev

@app.route('/receiveKey', methods=['POST'])
def receiveKey():
    # Ask the host to get us onboarded
    encrypted_message = request.data

    # Decrypt the message using the private key
    unseal_box = SealedBox(private_key)
    decrypted_message = unseal_box.decrypt(encrypted_message)
    xPriv = bytes(decrypted_message)



#####################
# Onboard
#####################
# Called by the host, to help someone else onboard

@app.route('/onboard', methods=['POST'])
def onboard():
    pubk = request.form['pubk']
    quote = request.form['quote']

    # Verify signature chains in the quote
    obj = verify_quote(quote)
    FMSPC = obj['fmspc']

    # Recompute the appdata we're expecting
    ref_report_data = extend_report_data("request", pubk)
    
    # Verify the quote in the blob against expected measurement
    assert(obj['report_data'].startswith(ref_report_data))

    # Encrypt the entire global state as a messsage
    global global_state
    message = json.dumps(global_state)

    # Encrypt a message using the public key
    p = PublicKey(bytes.fromhex(pubk))
    sealed_box = SealedBox(p)
    encrypted_message = bytes(sealed_box.encrypt(xPriv)).hex()

    return encrypted_message.hex(), 200


# Return a summary of status
@app.route('/status', methods=['GET'])
def status():
    ip_address = request.remote_addr
    d = dict(caller_address=ip_address)
    
    global global_state
    d.update(global_state)
    
    # Sanitize
    if 'xPriv' in d: del d['xPriv']
    if 'myPriv' in d: del d['myPriv']
    return d


##############################
# Dstack cooperative interface
##############################

# Called by other trusted modules to get a derived key
@app.route('/getkey/', methods=['GET'])
def getkey(tag):
    ip_address = request.remote_addr

    h = hashlib.blake2b(ip_address.encode('utf-8'), key=xPriv, digest_size=32)
    return h.hexdigest()

# Called by other trusted modules to do EVM-friendly attestation
@app.route('/appdata/<tag>/<appdata>', methods=['GET'])
def get_appdata(tag, appdata):
    ip_address = request.remote_addr
    appdata = keccak(tag.encode('utf-8') + bytes.fromhex(appdata))
    return appdata

# Remote attestations (using signature from address)
@app.route('/attest/<tag>/<appdata>', methods=['GET'])
def attest(tag, appdata):
    ip_address = request.remote_addr
    appdata = keccak(tag.encode('utf-8') + bytes.fromhex(appdata))
    h = keccak(b"attest" + appdata)
    sig = Account.from_key(xPriv).unsafe_sign_hash(h)
    sig = sig.v.to_bytes(1,'big') +  sig.r.to_bytes(32,'big') + sig.s.to_bytes(32,'big')
    return sig

@app.errorhandler(404)
def not_found(e):
    return "Not Found", 404

if __name__ == '__main__':
    port = 4001
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    app.run(host='0.0.0.0', port=port)
