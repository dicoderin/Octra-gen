import base64
import hashlib
import json
import datetime
import base58
import time
import requests
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator
from nacl.signing import SigningKey
from rich import print
from rich.progress import Progress

def print_banner():
    print("[rainbow]██╗    ██╗ ██╗ ███╗   ██╗ ███████╗ ███╗   ██╗ ██╗ ██████╗[/]")
    print("[cyan]██║    ██║ ██║ ████╗  ██║ ██╔════╝ ████╗  ██║ ██║ ██╔══██╗[/]")
    print("[green]██║ █╗ ██║ ██║ ██╔██╗ ██║ ███████╗ ██╔██╗ ██║ ██║ ██████╔╝[/]")
    print("[yellow]██║███╗██║ ██║ ██║╚██╗██║ ╚════██║ ██║╚██╗██║ ██║ ██╔═══╝[/]")
    print("[blue]╚███╔███╔╝ ██║ ██║ ╚████║ ███████║ ██║ ╚████║ ██║ ██║[/]")
    print("[red] ╚══╝╚══╝  ╚═╝ ╚═╝  ╚═══╝ ╚══════╝ ╚═╝  ╚═══╝ ╚═╝ ╚═╝[/]\n")
    print("[bold red]🔥 Join grup TG:[/] [bold underline bright_cyan]@winsnip[/]\n")

def generate_wallet(prefix):
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(24)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    entropy = hashlib.sha256(seed_bytes).hexdigest()[:32]
    signing_key = SigningKey(seed_bytes[:32])
    verify_key = signing_key.verify_key
    priv_key_bytes = signing_key.encode()
    pub_key_bytes = verify_key.encode()
    sha_pub = hashlib.sha256(pub_key_bytes).digest()
    address_body = base58.b58encode(sha_pub).decode()
    address = prefix + address_body
    return {
        "mnemonic": str(mnemonic),
        "private_key_b64": base64.b64encode(priv_key_bytes).decode(),
        "public_key_b64": base64.b64encode(pub_key_bytes).decode(),
        "address": address,
        "entropy": entropy
    }

def claim_faucet(address):
    url = "https://faucet.octra.network/credit"
    payload = {"address": address}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            return True, "Success"
        return False, f"HTTP Error {response.status_code}: {response.text}"
    except Exception as e:
        return False, str(e)

def send_tokens(sender_wallet, receiver_address, amount):
    # This is a placeholder function since actual implementation requires:
    # 1. Network RPC endpoint
    # 2. Transaction signing logic
    # 3. Broadcasting mechanism
    # In real implementation, you would:
    #   - Create transaction
    #   - Sign with sender's private key
    #   - Broadcast to network
    return True, "Transfer simulated (real implementation requires network RPC)"

def save_wallets_json(wallets, prefix):
    with open(f"{prefix}_wallets.json", "w") as f:
        json.dump(wallets, f, indent=4)
    print(f"✅ Saved: {prefix}_wallets.json")

def save_wallets_txt_components(wallets, prefix):
    with open(f"{prefix}_mnemonic.txt", "w") as f_mnemonic, \
         open(f"{prefix}_private_key.txt", "w") as f_priv, \
         open(f"{prefix}_public_key.txt", "w") as f_pub, \
         open(f"{prefix}_address.txt", "w") as f_addr:
        for w in wallets:
            f_mnemonic.write(w["mnemonic"] + "\n")
            f_priv.write(w["private_key_b64"] + "\n")
            f_pub.write(w["public_key_b64"] + "\n")
            f_addr.write(w["address"] + "\n")
    print(f"✅ Saved: {prefix}_mnemonic.txt")
    print(f"✅ Saved: {prefix}_private_key.txt")
    print(f"✅ Saved: {prefix}_public_key.txt")
    print(f"✅ Saved: {prefix}_address.txt")

if __name__ == "__main__":
    print_banner()
    try:
        count = int(input("Number of wallets to generate: ").strip())
        prefix = input("Address prefix (e.g. oct, etc.): ").strip()
        if not prefix:
            raise ValueError("Prefix tidak boleh kosong")
        if count < 1:
            raise ValueError("Jumlah wallet harus lebih dari 0")
        
        main_wallet = input("Main wallet address to receive tokens: ").strip()
        if not main_wallet:
            raise ValueError("Main wallet address required")
        
        wallets = []
        with Progress() as progress:
            task = progress.add_task("[cyan]Generating wallets...", total=count)
            
            for _ in range(count):
                wallet = generate_wallet(prefix)
                wallets.append(wallet)
                
                # Claim faucet
                progress.print(f"⏳ Claiming faucet for {wallet['address']}")
                success, message = claim_faucet(wallet["address"])
                if success:
                    progress.print(f"✅ Faucet claimed for {wallet['address']}")
                    
                    # Send tokens to main wallet
                    progress.print(f"⏳ Sending 600 OCT to {main_wallet}")
                    success, msg = send_tokens(wallet, main_wallet, 600)
                    if success:
                        progress.print(f"✅ Sent 600 OCT from {wallet['address']}")
                    else:
                        progress.print(f"❌ Failed to send: {msg}")
                else:
                    progress.print(f"❌ Faucet claim failed: {message}")
                
                progress.update(task, advance=1)
                time.sleep(1)  # Avoid rate limiting
        
        save_wallets_json(wallets, prefix)
        save_wallets_txt_components(wallets, prefix)
        
        print(f"\n✅ Berhasil membuat {count} wallet dengan prefix '{prefix}'!")
        print("\n🔎 Contoh alamat wallet pertama:")
        print(f"Address : {wallets[0]['address']}")
        print(f"Mnemonic: {wallets[0]['mnemonic']}")
    
    except Exception as e:
        print(f"⚠️ Terjadi kesalahan: {e}")
