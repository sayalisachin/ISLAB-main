#Build a digital signing system that includes a timestamp to prevent replay attacks. Demonstrate how both the message and timestamp are signed, and how the receiver can validate it.
import hashlib
import json
from time import time
from digital_signature import DigitalSignature

class Block:
    def __init__(self, index, timestamp, message, signature, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.message = message
        self.signature = signature
        self.previous_hash = previous_hash

    def compute_hash(self):
        # Create a SHA-256 hash of the block
        block_string = json.dumps(self.__dict__, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block(previous_hash='0')  # Genesis block

    def create_block(self, message=None, signature=None, previous_hash=None):
        block = Block(
            index=len(self.chain) + 1,
            timestamp=time(),
            message=message,
            signature=signature,
            previous_hash=previous_hash or (self.chain[-1].compute_hash() if self.chain else '0')
        )
        self.chain.append(block)
        return block

    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Verify the hash of the previous block
            if current_block.previous_hash != previous_block.compute_hash():
                print(f"Block {i} has been tampered with!")
                return False
            
            # Verify the signature
            signer = DigitalSignature()
            if not signer.verify(current_block.message, current_block.signature, current_block.timestamp):
                print(f"Signature for block {i} is invalid!")
                return False
            
        print("Blockchain is valid!")
        return True


# Example Usage
if __name__ == "__main__":
    blockchain = Blockchain()

    # Create a signer and sign a message
    signer = DigitalSignature()
    message = "Hello, this is a message for the blockchain."
    
    signature, timestamp = signer.sign(message)

    # Add block to the blockchain
    blockchain.create_block(message=message, signature=signature.hex())

    # Verify the blockchain
    blockchain.verify_chain()
