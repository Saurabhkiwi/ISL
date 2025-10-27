import sys
import json
import time
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# =====================================================================
# [cite_start]1. PAILLIER FUNCTIONS (from Lab 7) [cite: 861, 993-995]
# =====================================================================

def generate_paillier_keys(bits=1024):
    public_key, private_key = paillier.generate_paillier_keypair(n_length=bits)
    return public_key, private_key

def paillier_encrypt(public_key, number):
    return public_key.encrypt(number)

def paillier_decrypt(private_key, encrypted_number):
    return private_key.decrypt(encrypted_number)

# =====================================================================
# 2. RSA SIGNING FUNCTIONS (from Lab 6)
# =====================================================================

def generate_rsa_signing_keys(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key # public_key, private_key

def rsa_pss_sign(private_key, hash_obj):
    signer = pss.new(private_key)
    return signer.sign(hash_obj)

def rsa_pss_verify(public_key, hash_obj, signature):
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
    return SHA256.new(data_string.encode('utf-8'))

# =====================================================================
# 4. SIMULATION CLASSES & DATA
# =====================================================================

class ElectionServer:
    """Acts as the SERVER."""
    def __init__(self):
        self.name = "Election Server"
        print(f"[{self.name}] Generating Paillier key pair for voting...")
        self.pk_paillier, self.sk_paillier = generate_paillier_keys()
        
        # Initialize the encrypted tally with an encryption of 0
        self.total_encrypted_tally = self.pk_paillier.encrypt(0)
        
        self.voter_public_keys = {}
        self.transaction_summary = []
        self.vote_inbox = []
        print(f"[{self.name}] Ready to accept votes.")

    def register_voter(self, voter):
        self.voter_public_keys[voter.voter_id] = voter.public_key
        print(f"[{self.name}] Registered Voter: {voter.voter_id}")
    
    def submit_vote_to_inbox(self, encrypted_vote, ballot_string, signature):
        """Voter 'sends' their vote, which lands in the server's inbox."""
        self.vote_inbox.append((encrypted_vote, ballot_string, signature))
        print(f"[Server] Encrypted vote received and is pending processing.")

    def process_pending_votes(self):
        """Processes all votes in the inbox."""
        if not self.vote_inbox:
            print(f"\n[{self.name}] No pending votes to process.")
            return

        print(f"\n[{self.name}] Processing {len(self.vote_inbox)} pending vote(s)...")
        
        while self.vote_inbox:
            encrypted_vote, ballot_string, signature = self.vote_inbox.pop(0)
            
            try:
                ballot_data = json.loads(ballot_string)
                voter_id = ballot_data["voter_id"]
            except Exception as e:
                print(f"[{self.name}] ERROR: Discarding corrupt ballot. {e}")
                continue

            summary_entry = {
                "Voter ID": voter_id,
                "Signature Verification Result": False,
                "Status": "Vote Discarded"
            }
            
            # 1. Look up voter's public key
            voter_rsa_pub_key = self.voter_public_keys.get(voter_id)
            if not voter_rsa_pub_key:
                print(f"[{self.name}] ERROR: Voter '{voter_id}' not registered. Vote discarded.")
                self.transaction_summary.append(summary_entry)
                continue
                
            # 2. Verify Signature
            hash_to_verify = hash_sha256(ballot_string)
            is_valid_signature = rsa_pss_verify(voter_rsa_pub_key, hash_to_verify, signature)
            
            if not is_valid_signature:
                print(f"[{self.name}] SIGNATURE FAILED for {voter_id}. Vote discarded.")
                summary_entry["Signature Verification Result"] = False
                self.transaction_summary.append(summary_entry)
                continue
            
            # 3. Signature is VALID. Homomorphically add the vote.
            print(f"[{self.name}] Signature Verified for {voter_id}. Adding vote to tally.")
            self.total_encrypted_tally = self.total_encrypted_tally + encrypted_vote
            
            summary_entry["Signature Verification Result"] = True
            summary_entry["Status"] = "Vote Added to Tally"
            self.transaction_summary.append(summary_entry)
            
        print(f"\n[{self.name}] All pending votes processed.")

    def get_final_results(self):
        """Decrypts the one and only total tally."""
        print(f"\n[{self.name}] --- ELECTION CLOSED ---")
        print(f"[{self.name}] Decrypting final tally...")
        final_tally = paillier_decrypt(self.sk_paillier, self.total_encrypted_tally)
        print(f"[{self.name}] FINAL 'YES' VOTE COUNT: {final_tally}")
        
    def print_transaction_summary(self):
        print("\n" + "="*50)
        print("        ELECTION TRANSACTION SUMMARY LOG")
        print("="*50)
        print(json.dumps(self.transaction_summary, indent=2))
        print("="*50)

class Voter:
    """Acts as the CLIENT."""
    def __init__(self, voter_id):
        self.voter_id = voter_id
        self.public_key, self.private_key = generate_rsa_signing_keys()
        print(f"[{self.voter_id} (Client)] RSA Signing Keys Generated.")

    def cast_vote(self, paillier_public_key, vote: int):
        """Creates and signs a ballot, returning all parts."""
        if vote not in [0, 1]:
            print(f"[{self.voter_id}] Invalid vote. Must be 0 or 1.")
            return None, None, None
            
        print(f"\n[{self.voter_id}] Casting vote: {'Yes' if vote == 1 else 'No'}")
        
        # [cite_start]1. Encrypt the vote [cite: 861]
        encrypted_vote = paillier_encrypt(paillier_public_key, vote)
        
        # 2. Create the ballot string
        ballot_data = {
            "voter_id": self.voter_id,
            "timestamp": time.time()
        }
        ballot_string = json.dumps(ballot_data, sort_keys=True)
        
        # 3. Hash the ballot
        hash_obj = hash_sha256(ballot_string)
        
        # 4. Sign the hash
        signature = rsa_pss_sign(self.private_key, hash_obj)
        
        print(f"[{self.voter_id}] Vote encrypted and ballot signed.")
        return encrypted_vote, ballot_string, signature

# --- Global Objects ---
server = ElectionServer()
voters = {
    "1": Voter("Voter_123"),
    "2": Voter("Voter_456")
}

# =====================================================================
# 5. MENU-DRIVEN LOGIC
# =====================================================================

def init_registration():
    print("\n--- Initializing Voter Registration ---")
    server.register_voter(voters["1"])
    server.register_voter(voters["2"])
    print("---------------------------------------")

def voter_menu():
    while True:
        print("\n--- Voter Menu (Client) ---")
        print("Select Voter:")
        print("  1. Voter_123")
        print("  2. Voter_456")
        print("\n  9. Back to Main Menu")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "9":
            return
        
        voter = voters.get(choice)
        if not voter:
            print("Invalid choice.")
            continue
            
        vote_choice = input(f"--- Actions for {voter.voter_id} ---\nEnter '1' for YES, '0' for NO: ").strip()
        
        if vote_choice == "1":
            vote = 1
        elif vote_choice == "0":
            vote = 0
        else:
            print("Invalid vote.")
            continue
            
        # Cast the vote and get the pieces
        enc_vote, ballot_str, sig = voter.cast_vote(server.get_paillier_public_key(), vote)
        
        if enc_vote:
            # "Send" the vote to the server's inbox
            server.submit_vote_to_inbox(enc_vote, ballot_str, sig)

def server_menu():
    while True:
        print("\n--- Election Server Menu (Server) ---")
        print(f"1. Process all pending votes ({len(server.vote_inbox)} in inbox)")
        print("2. Get FINAL Tally (Closes Election)")
        print("3. Display Transaction Summary Log")
        print("\n9. Back to Main Menu")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            server.process_pending_votes()
        elif choice == "2":
            server.get_final_results()
        elif choice == "3":
            server.print_transaction_summary()
        elif choice == "9":
            return
        else:
            print("Invalid choice.")

def main():
    init_registration()
    while True:
        print("\n" + "="*40)
        print("       Secure E-Voting Simulation")
        print("="*40)
        print("Select Your Role:")
        print("1. Voter (Client)")
        print("2. Election Server (Server)")
        print("3. Exit")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            voter_menu()
        elif choice == "2":
            server_menu()
        elif choice == "3":
            print("Exiting.")
            sys.exit()
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
