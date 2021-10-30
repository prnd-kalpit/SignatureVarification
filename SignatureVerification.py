import hashlib
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from cryptography.exceptions import InvalidSignature


public_pem = None
private_pem = None



def validate(message,signature):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        hash_string = json.dumps(message, sort_keys=True)
        encoded_hash_string = hash_string.encode('utf-8')
        
        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')

        # Signature - Encode to bytes and then Base64 Decode to get the original signature format back 
        signature = base64.b64decode(signature.encode('utf-8'))

        try:
            # Load the public_key object and verify the signature against the calculated hash
            sender_public_key = serialization.load_pem_public_key(public_pem)
            sender_public_key.verify(
                                        signature,
                                        encoded_message_hash,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ),
                                        hashes.SHA256()
                                    )
        except InvalidSignature:
            return False
        return True
       

   

def create_signature(message_object):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        message_string = "sjkdhjsjdhsjdhjsdhjshdjshds"# json.dumps(message_object, sort_keys=True)
        encoded_string = message_string.encode('utf-8')
        
        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')
        
        # Load the private_key object and sign the hash of the message
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        hash_signature = private_key.sign(
                                                    encoded_message_hash,
                                                    padding.PSS(
                                                        mgf=padding.MGF1(hashes.SHA256()),
                                                        salt_length=padding.PSS.MAX_LENGTH
                                                    ),
                                                    hashes.SHA256()
                                                )

        # Signature: Base64 encode and convert to unicode for easy viewability
        signature = base64.b64encode(hash_signature).decode('utf-8')

        return message_object,signature



if __name__ == "__main__":
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Assigning the public key from the pair
    public_key = private_key.public_key()
        
        # Serializing the private key data to a pem string
    private_pem = private_key.private_bytes(
                                                        encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.PKCS8,
                                                        encryption_algorithm=serialization.NoEncryption()
                                                    )

        # Serializing the public key data to a pem string
    public_pem = public_key.public_bytes(
                                                encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                            )

    messageToBeValidated= {"key":"my value"}     

    message,signature=create_signature(messageToBeValidated)
    result=validate(message,signature)
    if(result):
        print("validation successful")
    else:
        print("validation failure")
    