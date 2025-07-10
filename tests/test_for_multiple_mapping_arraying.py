import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.utils import extract_selectors_from_bytecode
from tools.utils import analyze_contract_storage
import json

from octopus.platforms.ETH.explorer import EthereumExplorerRPC
from config import NETWORK,RPC_URL



# === Configuration ===
explorer = EthereumExplorerRPC(full_url=RPC_URL)

contract_address = "0x9054B9BBe23d95Eb94C87a0eb1b4945528145F06" #ethereum mainnet diamond contract

# === Get selectors from bytecode ===
bytecode = explorer.eth_getCode(contract_address)
selectors = extract_selectors_from_bytecode(bytecode)
owner = "0x" + "cc" * 20
global_slot_usage,slot_layout = analyze_contract_storage( contract_address,selectors, explorer, owner)
print(json.dumps(global_slot_usage, indent=4))
print(json.dumps(slot_layout, indent=4))



