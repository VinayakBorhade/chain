from time import time
import hashlib
import json
from uuid import uuid4
from flask import Flask, jsonify, request
import requests
from urllib.parse import urlparse

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        # genesis block
        self.add_block(previous_hash='1', proof=12)
    

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
    
    def new_transaction(self, sender, recipient, amount):
        ts = {
            "sender": sender,
            "recipient": recipient,
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

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender', 'recipient', 'amount']

    if not all(k in values for k in required):
        return 'Missing Values', 400
    
    sender = values['sender']
    recipient = values['recipient']
    amount = values['amount']
    index = blockchain.new_transaction(sender,
                        recipient,amount)
    
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