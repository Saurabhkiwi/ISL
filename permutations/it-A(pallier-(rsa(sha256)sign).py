'''
*IS LAB ENDSEM QUESTION* : Client–Server Program for Seller and Payment Gateway

Develop a client–server application that simulates transactions between multiple sellers and a payment gateway, as per the following specifications:

1. Sellers and Transactions

Implement a minimum of two sellers.

Each seller should perform at least two or more transactions.



2. Paillier Encryption for Transaction Amounts

Each transaction amount must be encrypted using the Paillier encryption algorithm.

The encrypted amounts should be added homomorphically to compute the total encrypted transaction amount for each seller.

The total should then be decrypted to obtain the total decrypted amount.



3. Transaction Summary

Maintain a transaction summary for all sellers containing the following details:

Seller Name

Individual Transaction Amounts

Encrypted Transaction Amounts

Decrypted Transaction Amounts

Total Encrypted Transaction Amount

Total Decrypted Transaction Amount

Digital Signature Status

Signature Verification Result




4. Digital Signature and Verification

Generate and verify digital signatures using the RSA algorithm.

Apply SHA-256 hashing on the entire transaction summary before signing and verifying.



5. Output Requirements

Display the complete transaction summary for all sellers, including encryption, decryption, total amount computation, and signature verification results.
'''

import sys
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from phe import paillier

# =====================================================================
# [cite_start]1. PAILLIER ENCRYPTION FUNCTIONS (from Lab 7) [cite: 861, 993-995]
# =====================================================================

def generate_paillier_keys(bits=1024):
    """Generates Paillier public and private keys."""
    public_key, private_key = paillier.generate_paillier_keypair(n_length=bits)
    return public_key, private_key

def paillier_encrypt(public_key, number):
    """Encrypts a single number using Paillier."""
    # Paillier library requires floats/ints, not strings
    try:
        number_float = float(number)
        return public_key.encrypt(number_float)
    except ValueError:
        print(f"Error: Cannot encrypt non-numeric value '{number}'")
        return None

def paillier_decrypt(private_key, encrypted_number):
    """Decrypts a single Paillier-encrypted number."""
    return private_key.decrypt(encrypted_number)

# =====================================================================
# 2. RSA SIGNING FUNCTIONS (from Lab 6)
# =====================================================================

def generate_rsa_signing_keys(bits=2048):
    """Generates an RSA key pair for signing."""
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def rsa_pss_sign(private_key, hash_obj):
    """Signs a HASH OBJECT using the RSA private key with PSS."""
    signer = pss.new(private_key)
    signature = signer.sign(hash_obj)
    return signature

def rsa_pss_verify(public_key, hash_obj, signature):
    """Verifies an RSA-PSS signature against a HASH OBJECT."""
    verifier = pss.new(public_key)
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# =====================================================================
# 3. HASHING FUNCTION (from Lab 5)
# =====================================================================

def hash_sha256(data_string: str) -> SHA256.SHA256Hash:
    """Computes the SHA-256 hash of a string and returns the hash *object*."""
    return SHA256.new(data_string.encode('utf-8'))

# =====================================================================
# 4. GLOBAL OBJECTS & SIMULATION DATA
# =====================================================================

# Server Object
class PaymentGateway:
    """
    Acts as the SERVER.
    """
    def __init__(self):
        self.name = "Payment Gateway (Server)"
        # Gateway holds the central Paillier keys
        self.paillier_public_key, self.paillier_private_key = generate_paillier_keys()
        # Gateway stores registered seller public keys
        self.seller_rsa_keys = {}
        # This is the final, verified log
        self.final_transaction_summary = []
        # Inbox for pending batches
        self.pending_batches = []
        print(f"[{self.name}] Paillier Keys Generated.")

    def get_paillier_public_key(self):
        return self.paillier_public_key

    def register_seller(self, seller):
        self.seller_rsa_keys[seller.name] = seller.public_key
        print(f"[{self.name}] Registered Seller: {seller.name}")

    def submit_batch_to_inbox(self, seller_name, client_summary_string, encrypted_txns, signature):
        """Seller 'sends' a batch, which lands in the Gateway's inbox."""
        self.pending_batches.append(
            (seller_name, client_summary_string, encrypted_txns, signature)
        )
        print(f"[Gateway] Batch from '{seller_name}' received and is pending processing.")

    def process_pending_batches(self):
        """Processes all batches currently in the inbox."""
        if not self.pending_batches:
            print("\n[Gateway] No pending batches to process.")
            return

        print(f"\n[Gateway] Processing {len(self.pending_batches)} pending batch(es)...")
        
        # Process one batch at a time
        while self.pending_batches:
            # Get the oldest batch (First-In, First-Out)
            seller_name, client_summary_string, encrypted_txns, signature = self.pending_batches.pop(0)
            
            print(f"\n[Gateway] Processing batch from: {seller_name}...")
            
            # 1. Find the seller's registered public key
            seller_rsa_pub_key = self.seller_rsa_keys.get(seller_name)
            if not seller_rsa_pub_key:
                print(f"[Gateway] ERROR: Seller '{seller_name}' not registered. Batch skipped.")
                continue

            # 2. Hash the received summary string
            hash_to_verify = hash_sha256(client_summary_string)
            
            # 3. Verify the digital signature
            is_valid_signature = rsa_pss_verify(seller_rsa_pub_key, hash_to_verify, signature)
            
            # 4. Create the final summary report
            final_summary_entry = json.loads(client_summary_string)
            final_summary_entry["Digital Signature Status"] = "Verified" if is_valid_signature else "FAILED"
            final_summary_entry["Signature Verification Result"] = is_valid_signature
            
            if not is_valid_signature:
                print(f"[Gateway] SIGNATURE VERIFICATION FAILED for {seller_name}.")
                self.final_transaction_summary.append(final_summary_entry)
                continue
                
            print(f"[Gateway] Signature Verified for {seller_name}.")

            # 5. Perform Paillier operations
            total_encrypted = sum(encrypted_txns)
            total_decrypted = paillier_decrypt(self.paillier_private_key, total_encrypted)
            decrypted_individuals = [paillier_decrypt(self.paillier_private_key, c) for c in encrypted_txns]
            
            # 6. Add final data to the summary
            final_summary_entry['Decrypted Transaction Amounts'] = decrypted_individuals
            final_summary_entry['Total Encrypted Transaction Amount (Hex)'] = hex(total_encrypted.ciphertext())
            final_summary_entry['Total Decrypted Transaction Amount'] = total_decrypted
            
            print(f"[Gateway] Successfully processed batch. Decrypted Total: {total_decrypted}")
            self.final_transaction_summary.append(final_summary_entry)
        
        print("\n[Gateway] All pending batches processed.")


    def print_final_summary(self):
        """Prints the complete transaction summary for all sellers."""
        if not self.final_transaction_summary:
            print("\n[Gateway] Transaction summary is empty.")
            return

        print("\n" + "="*70)
        print("           FINAL PAYMENT GATEWAY TRANSACTION SUMMARY")
        print("="*70)
        print(json.dumps(self.final_transaction_summary, indent=2))

# Client Object
class Seller:
    """
    Acts as the CLIENT.
    """
    def __init__(self, name):
        self.name = name
        # Sellers hold their own RSA keys for signing
        self.public_key, self.private_key = generate_rsa_signing_keys()
        print(f"[{self.name} (Client)] RSA Signing Keys Generated.")
    
    def get_rsa_public_key(self):
        """For registering with the gateway."""
        return self.public_key

    def create_transaction_batch(self, gateway_paillier_pk, transaction_amounts):
        """
        Creates a batch of encrypted transactions and signs a summary.
        """
        print(f"\n[Seller '{self.name}'] Creating batch for transactions: {transaction_amounts}")
        
        # 1. Encrypt transaction amounts
        try:
            encrypted_txns = [paillier_encrypt(gateway_paillier_pk, amt) for amt in transaction_amounts]
        except ValueError as e:
            print(f"[Seller '{self.name}'] ERROR: Invalid transaction amount. {e}")
            return None, None, None
            
        print(f"[Seller '{self.name}'] Encrypted {len(encrypted_txns)} transactions.")

        # 2. Create the transaction summary
        client_summary = {
            "Seller Name": self.name,
            "Individual Transaction Amounts": transaction_amounts,
            "Encrypted Transaction Amounts (Hex)": [hex(c.ciphertext()) for c in encrypted_txns]
        }
        
        # 3. Convert summary to a string for hashing
        summary_string = json.dumps(client_summary, sort_keys=True)
        
        # 4. Hash the summary string
        hash_obj = hash_sha256(summary_string)
        print(f"[Seller '{self.name}'] Hashed summary: {hash_obj.hexdigest()}")
        
        # 5. Sign the hash
        signature = rsa_pss_sign(self.private_key, hash_obj)
        print(f"[Seller '{self.name}'] Signed hash with private key.")
        
        return summary_string, encrypted_txns, signature

# --- Simulation Data Stores ---
# This acts as the "network" inbox for pending transactions
global_inbox = []
# This stores the global server object
gateway = PaymentGateway()
# This stores the client objects
sellers = {
    "1": Seller("Seller 1 (Gadget World)"),
    "2": Seller("Seller 2 (Book Haven)")
}

# =====================================================================
# 6. MENU-DRIVEN LOGIC
# =====================================================================

def init_registration():
    """Register all sellers with the gateway at startup."""
    print("\n--- Initializing Seller Registration ---")
    gateway.register_seller(sellers["1"])
    gateway.register_seller(sellers["2"])
    print("----------------------------------------")

def seller_menu():
    """Menu for handling seller actions."""
    while True:
        print("\n--- Seller Menu (Client) ---")
        print("Select a Seller:")
        print("  1. Seller 1 (Gadget World)")
        print("  2. Seller 2 (Book Haven)")
        print("\n  9. Back to Main Menu")  # <-- CORRECTED
        
        choice = input("Enter choice: ").strip()
        
        if choice == "9":  # <-- CORRECTED
            return
        
        seller = sellers.get(choice)
        if not seller:
            print("Invalid choice, please try again.")
            continue
            
        # --- Seller-Specific Actions ---
        print(f"\n--- Actions for {seller.name} ---")
        print("1. Create and send new transaction batch")
        print("2. Back to Seller Selection")
        
        action_choice = input("Enter action: ").strip()
        
        if action_choice == "1":
            try:
                amounts_str = input("Enter transaction amounts (e.g., 120.50, 75.00): ")
                # Convert list of strings to list of floats
                amounts = [float(amt.strip()) for amt in amounts_str.split(',')]
                
                if not amounts:
                    print("No amounts entered.")
                    continue
                    
                # Get the gateway's public key
                gateway_pk = gateway.get_paillier_public_key()
                
                # Seller creates the batch
                summary_str, enc_txns, sig = seller.create_transaction_batch(gateway_pk, amounts)
                
                if summary_str:
                    # Seller "sends" the batch to the gateway's inbox
                    gateway.submit_batch_to_inbox(seller.name, summary_str, enc_txns, sig)
                    print(f"[Seller '{seller.name}'] Batch successfully sent to gateway.")
                
            except ValueError:
                print("Invalid input. Please enter numbers separated by commas.")
            except Exception as e:
                print(f"An error occurred: {e}")
                
        elif action_choice == "2":
            continue # This goes back to "Select a Seller"

def gateway_menu():
    """Menu for handling gateway actions."""
    while True:
        print("\n--- Payment Gateway Menu (Server) ---")
        # Update the inbox count correctly
        print(f"1. Process all pending transaction batches ({len(global_inbox)} in inbox)")
        print("2. Display Final Transaction Summary")
        print("\n9. Back to Main Menu")  # <-- CORRECTED
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            # --- THIS IS THE FIX ---
            # Call the method on the 'gateway' object
            gateway.process_pending_batches() 
            # --- END FIX ---
        elif choice == "2":
            # --- THIS IS THE FIX ---
            # Call the method on the 'gateway' object
            gateway.print_final_summary() 
            # --- END FIX ---
        elif choice == "9":  # <-- CORRECTED
            return
        else:
            print("Invalid choice, please try again.")

def main():
    """Main menu to select role."""
    # Register sellers once at the start
    init_registration()
    
    while True:
        print("\n" + "="*40)
        print("   Paillier & RSA Signature Simulation")
        print("="*40) # <-- CORRECTED TYPO
        print("Select Your Role:")
        print("1. Seller (Client)")
        print("2. Payment Gateway (Server)")
        print("3. Exit")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            seller_menu()
        elif choice == "2":
            gateway_menu()
        elif choice == "3":
            print("Exiting simulation.")
            sys.exit()
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
