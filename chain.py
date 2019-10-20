from time import time
import hashlib
import json
from uuid import uuid4
from flask import Flask, jsonify, request
import requests
from urllib.parse import urlparse
from collections import OrderedDict
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import rsa

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        # genesis block
        self.add_block(previous_hash='1', proof=12)
        self.wallets=[]
    

    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("URL Invalid")

    
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False
            
            if not self.validate(last_block['proof'],
                        block['proof'], last_block_hash):
                return False
            last_block = block
            current_index += 1
        return True
    
    def resolve_conflicts(self):
        neighbors = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbors:
            url = f'http://{node}/chain'
            response = requests.get(url)

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain  = chain
        
        if new_chain:
            self.chain = new_chain
            return True
        return False




    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]
    
    def new_transaction(self, sender, recipient, signature, amount):
        ts = {
            "sender": sender,
            "recipient": recipient,
            "signature": signature,
            "amount": amount
        }
        self.current_transactions.append(ts)
        return self.last_block["index"] + 1
    
    def add_block(self, proof, previous_hash):
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time(),
            "transactions": self.current_transactions,
            "proof": proof,
            "previous_hash": previous_hash or self.hash(self.chain[-1])
        }

        self.current_transactions = []
        self.chain.append(block)
        return block
    
    @staticmethod
    def validate(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def proof_of_work(self, last_block):
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.validate(last_proof, proof, last_hash) is False:
            proof += 1
        
        return proof


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-','')

blockchain = Blockchain()

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    blockchain.new_transaction(
        sender='0',
        recipient=node_identifier,
        signature='0',
        amount=20
        )
    previous_hash = blockchain.hash(last_block)
    block = blockchain.add_block(proof, 
                        previous_hash)
    
    response = {
        "message": "Block is created",
        "index": block['index'],
        "transactions": block['transactions'],
        "proof": block['proof'],
        "previous_hash" : block['previous_hash']
    }

    return jsonify(response), 200

def verify_transaction_signature(sender_address, signature, transaction):
	"""
	Check that the provided signature corresponds to transaction
	signed by the public key (sender_address)
	"""
	public_key = RSA.importKey(binascii.unhexlify(sender_address))
	verifier = PKCS1_v1_5.new(public_key)
	h = SHA.new(str(transaction).encode('utf8'))
	return verifier.verify(h, binascii.unhexlify(signature))

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender_wallet', 'recipient_wallet', 'signature', 'amount']

    if not all(k in values for k in required):
        return 'Missing Values', 400
    
    sender = values['sender_wallet']
    recipient = values['recipient_wallet']
    signature = values['signature']
    amount = int(values['amount'])
    
    sender_wallet=None
    recipient_wallet=None
    for wallet in blockchain.wallets:
    	if wallet['wallet_address']==sender:
    		sender_wallet=wallet
    	if wallet['wallet_address']==recipient:
    		recipient_wallet=wallet
    if sender_wallet is None :
    	return "no such wallet exists", 400
    if recipient_wallet is None:
    	return "no such wallet exists", 400
    if sender_wallet['amount']<amount:
    	return "not enough balance", 400
    
    transaction=OrderedDict({
        'sender_address': sender, 
        'recipient_address': recipient, 
        'value': amount})
    transaction_verification=verify_transaction_signature(sender, signature, transaction)
    print("verfication: ", transaction_verification)
    if transaction_verification==False:
        return "invalid signature, please recheck it", 400
    
    index = blockchain.new_transaction(sender, recipient, signature, amount)
    
    sender_wallet["amount"]-=amount
    recipient_wallet["amount"]+=amount
    
    response = {
        'message': f'Block #{index}'
        }
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = json.loads(request.data)
    nodes = values.get('nodes')

    if nodes is None:
        return 'Error', 400
    
    for node in nodes:
        blockchain.register_node(
            "http://127.0.0.1:" + str(node)
        )
    
    response = {
        'message': "Added new nodes",
        'total_nodes': list(blockchain.nodes)
    }

    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': "replaced",
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': "no change"
        }
    
    return jsonify(response), 200
    
@app.route('/wallet/new', methods=['POST'])
def wallet_new():
	random_gen = Crypto.Random.new().read
	private_key = RSA.generate(1024, random_gen)
	public_key = private_key.publickey()
	# (public_key, private_key) = rsa.newkeys(1024)
	# public_key=public_key.save_pkcs1(format='PEM')
	# private_key=private_key.save_pkcs1(format='PEM')
	response = {
		'message': 'wallet created successfully, please keep your keys protected and private',
		'wallet_address': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}
	wallet={
		"public_key": binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
		"wallet_address": binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
		"amount": 0
	}
	blockchain.wallets.append(wallet)
	return jsonify(response), 201
	
@app.route('/wallet/balance', methods=['GET'])
def wallet_balance():
	wallet_address=request.headers['wallet_address']
	balance=-1
	flag=False
	for wallet in blockchain.wallets:
		if wallet['public_key']==wallet_address:
			balance=wallet['amount']
			flag=True
			break
	if flag==False:
		return jsonify({
			'message':'wallet is invalid'
		}), 404
	return jsonify({
		'wallet balance: ': balance
	}), 200

@app.route('/transaction/sign', methods=['GET'])
def transaction_sign():
	sender_wallet=request.headers['sender_wallet']
	recipient_wallet=request.headers['recipient_wallet']
	private_key=request.headers['private_key']
	amount=int(request.headers['amount'])
	transaction=Transaction(sender_wallet, private_key, recipient_wallet, amount)
	signature=transaction.sign_transaction()
	return jsonify({
		'signature': signature
	}), 200


if __name__ == "__main__":
    from argparse import ArgumentParser
    print(node_identifier)
    parser = ArgumentParser()

    parser.add_argument('-p', '--port',
                        default=5000,
                        type=int,
                        help="port num")
    
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, 
            debug=True)
