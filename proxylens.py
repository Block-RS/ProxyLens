import sys
from tools.utils import diamond_selector_map_with_facets
from tools.utils import extract_selectors_from_bytecode
from tools.utils import extract_owner
from tools.utils import extract_delegatecall_slot
from tools.utils import extract_selector_and_impl_from_logic
from tools.utils import extract_beacon_selectors
from tools.utils import analyze_contract_storage
from tools.utils import merge_slot_profiles
from tools.utils import merge_global_slot_usages
from tools.utils import generate_audit_report

from tools.oracles import check_if_selector_collides
from tools.oracles import check_storage_conflict
from tools.oracles import check_Missing_Initialization
from tools.oracles import check_Missing_permission_control

from octopus.platforms.ETH.explorer import EthereumExplorerRPC
from config import NETWORK,RPC_URL



# === Configuration ===
explorer = EthereumExplorerRPC(full_url=RPC_URL)

# contract_address = "0xEEb00E283259d5E1930f27c62552A6a6BE510348" #ethereum mainnet diamond contract

#get proxy address from terminal
if len(sys.argv) < 2:
    print(f"[x] Usage: python {sys.argv[0]} <contract_address>")
    sys.exit(1)
contract_address = sys.argv[1].strip()

#check if contract address is valid
if not (contract_address.startswith("0x") and len(contract_address) == 42):
    print("[x] Invalid contract address format! Please enter a valid 42-character Ethereum address starting with '0x'.")
    sys.exit(1)

delegatecall_addr = {}
beacon_addr = None
beacon_bytecode = None
selectors_from_logic = None   #only store the selector map for single-logic contract
impl_addr = None  # store the impl address for single-logic contract
facet_addrs = None # store the impl address for diamond contract
logic_slot_layout = None

selectors = set()
bytecode_proxy_selectors = set()
abi_selectors = set()
selectors_from_proxy = set()
selectors_from_beacon = set()
diamond_selectors= set()

if_selectors_collide = False
has_conflict = False
if_initialization_missing = False
has_permission_missing = False


if_selectors_collide= None,
collision_selectors_detail_list=None,
storage_conflicts_detail_list=None,
uninitialized_slots_detail_list=None,
permission_check_summary=None,
diamond_storage_conflicts_detail_list=None
complete_slot_layout = None


# === Get selectors from bytecode ===
bytecode = explorer.eth_getCode(contract_address)
bytecode_proxy_selectors = extract_selectors_from_bytecode(bytecode)
selectors = selectors.union(bytecode_proxy_selectors) 

# === Get selectors from diamond proxy facets (on-chain call) ===
print("[+] Trying to analyze proxy pattern")
diamond_selector_map_raw, facet_addrs, is_diamond = diamond_selector_map_with_facets(explorer, contract_address)
if not is_diamond:
    #try to extract implememtation address
    selectors_from_logic,impl_addr = extract_selector_and_impl_from_logic(explorer, contract_address,bytecode)
    if  not impl_addr:
        print(f"[x] This contract is not a proxy contract,please offer a proxy contract address from {NETWORK} network")
        sys.exit(0)
    selectors_from_beacon,beacon_addr,beacon_bytecode,is_beacon = extract_beacon_selectors(contract_address, bytecode,{impl_addr},explorer, verbose=False)
    if is_beacon:
        print("[√] This contract is a Beacon proxy")
    else:
        print("[√] This contract is a Standard proxy")
    delegatecall_addr = {impl_addr}
else:
    print("[√] This contract is a Diamond proxy")
    selectors_from_logic = set(diamond_selector_map_raw.keys()) 
    delegatecall_addr = facet_addrs 
selectors = selectors.union(selectors_from_logic)
print(f"[+] Number of Selectors in Proxy Contract: {len(selectors_from_proxy)}")
if not is_diamond:
    print(f"[+] Number of Selectors in Logic Contract: {len(selectors_from_logic)}")
    if beacon_addr:
        print(f"[+] Number of Selectors in Beacon Contract: {len(selectors_from_beacon)}")
else:
    print(f"[+] Number of Selectors in Diamond Facets: {len(selectors_from_logic)}")
# === Check if selector collides ===
selectors_from_proxy = bytecode_proxy_selectors



# === Try to identify the owner slot ===
print("[+] Trying to extract owner")
if beacon_addr == None:
    owner,owner_slot,owner_mask = extract_owner(contract_address, bytecode,selectors, delegatecall_addr,explorer, verbose=True)
else:   
    owner,owner_slot,owner_mask = extract_owner(beacon_addr,beacon_bytecode, selectors_from_beacon, delegatecall_addr,explorer, verbose=True)
if owner == None:
    owner = "0x" + "cc" * 20


# === Try to identify the delegatecall slot ===
print("[+] Trying to extract logic addresses")
delegatecall_slot_map = extract_delegatecall_slot(contract_address, bytecode,owner,is_diamond,selectors, delegatecall_addr,explorer, verbose=True)

# === Prepare sensitive_slots_detail_list ===
sensitive_slots_detail_list = []
# Add owner slot
if owner_slot is not None and owner_mask is not None:
    sensitive_slots_detail_list.append((
        "owner",
        owner_slot,
        owner_mask
    ))

# Add logic address slot(s)
for logic_addr, (storage_address, slot_id_int) in delegatecall_slot_map.items():
    sensitive_slots_detail_list.append((
        "logic_address",
        slot_id_int,
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  # full mask
    ))


# === Try to identify the slot layout of the contract ===
proxy_global_slot_usage,proxy_slot_layout =  analyze_contract_storage(contract_address,selectors_from_proxy, explorer, owner)

if not is_diamond:
    if_selectors_collide,collision_selectors_detail_list  = check_if_selector_collides(
        proxy_address=contract_address,
        proxy_selectors=selectors_from_proxy,
        logic_selectors_set = selectors_from_logic,
        selectors_from_diamond=None,
        is_diamond=False,
    )
    # === Try to justify if there is storage collision between Proxy and newest Logic contract ===
    logic_global_slot_usage,logic_slot_layout = analyze_contract_storage( impl_addr,selectors_from_logic, explorer, owner)
    has_conflict,storage_conflicts_detail_list  = check_storage_conflict(proxy_slot_layout,logic_slot_layout,False)

    if beacon_addr == None:
    # None beacon modd
        complete_slot_layout = merge_slot_profiles(proxy_slot_layout,logic_slot_layout)
        global_slot_usage = merge_global_slot_usages(proxy_global_slot_usage,logic_global_slot_usage)
        if_initialization_missing,uninitialized_slots_detail_list = check_Missing_Initialization(
            contract_address,
            bytecode,
            complete_slot_layout,
            selectors,
            global_slot_usage,
            explorer
        )
        has_permission_missing,permission_check_summary = check_Missing_permission_control(
            contract_address,
            bytecode,
            owner,
            owner_slot,
            owner_mask,
            delegatecall_slot_map,
            selectors,
            explorer
        )
    else:
        # beacon mode
        beacon_global_slot_usage, beacon_slot_layout = analyze_contract_storage(
            beacon_addr,
            selectors_from_beacon,
            explorer,
            owner
        )
        complete_slot_layout = beacon_slot_layout
        global_slot_usage = beacon_global_slot_usage
        if_initialization_missing,uninitialized_slots_detail_list  = check_Missing_Initialization(
            beacon_addr,
            beacon_bytecode,
            complete_slot_layout,
            selectors_from_beacon,
            global_slot_usage,
            explorer
        )
        has_permission_missing,permission_check_summary = check_Missing_permission_control(
            beacon_addr,
            beacon_bytecode,
            owner,
            owner_slot,
            owner_mask,
            delegatecall_slot_map,
            selectors_from_beacon,
            explorer
        )


    
else:
    # complete storage layout of diamond proxy contract
    complete_global_slot_usage,complete_slot_layout =  analyze_contract_storage(contract_address,selectors, explorer, owner)

    if_selectors_collide,collision_selectors_detail_list = check_if_selector_collides(
        proxy_address=contract_address,
        proxy_selectors=selectors_from_proxy,
        logic_selectors_set=None,
        selectors_from_diamond=diamond_selector_map_raw,
        is_diamond=True,
    )
    
    # === Analyze storage layout for all facets ===
    # Prepare lists for merge later
    facet_slot_layout_list = []
    facet_global_slot_usage_list = []

    # Prepare conflict_details collector
    diamond_storage_conflicts_detail_list = []

    for facet_addr in set(diamond_selector_map_raw.values()):
        # Skip proxy itself to avoid duplicate self-checking
        if facet_addr.lower() == contract_address.lower():
            continue
        try:
            facet_selectors = set([
                selector for selector, addr in diamond_selector_map_raw.items()
                if addr.lower() == facet_addr.lower()
            ])

            facet_global_slot_usage, facet_slot_layout = analyze_contract_storage(
                facet_addr,   
                facet_selectors,
                explorer,
                owner
            )

            # Save for later merge
            facet_slot_layout_list.append(facet_slot_layout)
            facet_global_slot_usage_list.append(facet_global_slot_usage)

            # === Check storage conflict between proxy and current facet ===
            has_conflict, conflict_details = check_storage_conflict(proxy_slot_layout, facet_slot_layout, False)

            # Add facet address info to conflict_details
            for slot, mask, conflict_type, detail_1, detail_2 in conflict_details:
                diamond_storage_conflicts_detail_list.append((
                    facet_addr,
                    slot,
                    mask,
                    conflict_type,
                    detail_1,
                    detail_2
                ))

        except Exception as e:
            print(f"[!] WARNING: Failed to analyze facet {facet_addr}: {e}")
            continue

    # Use your merge functions with *args
    slot_layout = merge_slot_profiles(proxy_slot_layout, *facet_slot_layout_list)
    global_slot_usage = merge_global_slot_usages(proxy_global_slot_usage, *facet_global_slot_usage_list)

    # Run initialization missing check
    if_initialization_missing,uninitialized_slots_detail_list  = check_Missing_Initialization(
        contract_address,
        bytecode,
        slot_layout,
        selectors,  # already union of proxy selectors + logic selectors
        global_slot_usage,
        explorer
    )


    # === Check missing permission control (on proxy itself) ===
    has_permission_missing,permission_check_summary = check_Missing_permission_control(
        contract_address,
        bytecode,
        owner,
        owner_slot,
        owner_mask,
        delegatecall_slot_map,
        selectors,
        explorer
    )


# === Call report generation ===
audit_report_text = generate_audit_report(
    contract_address=contract_address,
    selectors_from_proxy = selectors_from_proxy ,
    selectors_from_logic = selectors_from_logic,
    selectors_from_beacon = selectors_from_beacon,
    beacon_addr = beacon_addr,
    facet_addrs = facet_addrs,
    impl_addr = impl_addr,
    global_layout = complete_slot_layout,
    if_selectors_collide=if_selectors_collide,
    collision_selectors_detail_list=collision_selectors_detail_list,
    has_conflict=has_conflict,
    storage_conflicts_detail_list=storage_conflicts_detail_list,
    if_initialization_missing=if_initialization_missing,
    uninitialized_slots_detail_list=uninitialized_slots_detail_list,
    has_permission_missing = has_permission_missing,
    permission_check_summary=permission_check_summary,
    is_diamond=is_diamond,
    diamond_storage_conflicts_detail_list=diamond_storage_conflicts_detail_list if is_diamond else None,
    sensitive_slots_detail_list=sensitive_slots_detail_list
)

with open("audit_report.md", "w") as f:
    f.write(audit_report_text)

print("[√] Audit report generated: audit_report.md")


    









