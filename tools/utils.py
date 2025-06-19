from eth_abi.codec import ABICodec
from eth_abi.registry import registry
from octopus.platforms.ETH.disassembler import EthereumDisassembler
import re
import json


from octopus.platforms.ETH.disassembler import EthereumDisassembler
from octopus.platforms.ETH.vmstate import EthereumVMstate
from octopus.platforms.ETH.emulator import EthereumSSAEngine


# === Generate Audit Report ===
from datetime import datetime

def generate_audit_report(proxy_pattern,contract_address,
                          selectors_from_proxy ,selectors_from_logic ,
                          selectors_from_beacon,beacon_addr,global_layout,
                          if_selectors_collide, collision_selectors_detail_list,
                          facet_addrs,impl_addr,
                          has_conflict, storage_conflicts_detail_list,
                          if_initialization_missing, uninitialized_slots_detail_list,
                          permission_check_summary,
                          has_permission_missing = False,
                          is_diamond=False,
                          diamond_storage_conflicts_detail_list=None,
                          sensitive_slots_detail_list = None,
                          ):
    
    def bool_to_status(value):
        return "Found" if value else "Not Found"

    def severity(value):
        return "High" if value else "Low"

    report_lines = []

    # Contract Info
    report_lines.append(f"# Proxy Contract Audit Report")
    report_lines.append(f"## Contract Address\n- {contract_address}\n")
    report_lines.append(f"## Report Summary\n- Date: {datetime.now().strftime('%Y-%m-%d')}\n")

    # Proxy Type
    report_lines.append(f"## Proxy Type\n- {proxy_pattern}\n")

    # Logic / Beacon / Facets Address
    report_lines.append("## Logic / Facets / Beacon Address")
    if is_diamond:
        report_lines.append("- Facet Addresses:")
        for facet_addr in sorted(facet_addrs):
            report_lines.append(f"    - {facet_addr}")
    else:
        if beacon_addr:
            report_lines.append(f"- Beacon Contract Address: {beacon_addr}")
        if impl_addr:
            report_lines.append(f"- Logic Contract Address: {impl_addr}")
        else:
            report_lines.append(f"- Logic Contract Address: N/A")  # fallback
    report_lines.append("")

    # Selectors Overview
    report_lines.append(f"## Selectors Overview")
    report_lines.append(f"- Number of Selectors in Proxy Contract: {len(selectors_from_proxy)}")
    if not is_diamond:
        report_lines.append(f"- Number of Selectors in Logic Contract: {len(selectors_from_logic)}")
        if beacon_addr:
            report_lines.append(f"- Number of Selectors in Beacon Contract: {len(selectors_from_beacon)}")
    else:
        report_lines.append(f"- Number of Selectors in Diamond Facets: {len(selectors_from_logic)}")
    report_lines.append("")

    # Storage Layout Overview
    report_lines.append("## Storage Layout Overview (Proxy Slot Layout)")
    report_lines.append("> Note: Slots used by mappings or dynamic arrays may not appear explicitly in this layout, as their storage is computed dynamically via keccak(slot . key). Only the base slot of such variables will appear here. Also, some variable's type may remain unkonwn due to insufficient context")
    existing_slots = set()

    for slot_id, subslots in global_layout.items():
        existing_slots.add(int(slot_id))  
        for mask_str, subslot_info in subslots.items():
            var_type = subslot_info.get("type", "unknown")
            report_lines.append(f"    - Slot {slot_id} Mask {mask_str} → Type: {var_type}")

    report_lines.append("\n---\n")


    # Summary Table
    report_lines.append("### Overall Result")
    report_lines.append("| Issue Category                  | Status  | Severity |")
    report_lines.append("|--------------------------------|---------|----------|")
    report_lines.append(f"| Function Selector Collisions    | {bool_to_status(if_selectors_collide)} | {severity(if_selectors_collide)} |")
    report_lines.append(f"| Storage Conflicts               | {bool_to_status(has_conflict)} | {severity(has_conflict)} |")
    report_lines.append(f"| Initialization Missing          | {bool_to_status(if_initialization_missing)} | {severity(if_initialization_missing)} |")
    report_lines.append(f"| Permission Control Missing      | {bool_to_status(has_permission_missing)} | {severity(has_permission_missing)} |")

    report_lines.append("\n---\n")

    # 1️ Function Selector Collision
    report_lines.append("## 1. Function Selector Collision Analysis")
    report_lines.append(f"- Number of Collisions Found: {len(collision_selectors_detail_list)}")
    report_lines.append("- Collided Selectors:")
    for selector, location in collision_selectors_detail_list:
        report_lines.append(f"    - {selector} → {location}")
    report_lines.append("\n---\n")

    # 2️ Storage Conflict
    report_lines.append("## 2. Storage Conflict Analysis")
    if is_diamond:
        report_lines.append("- Proxy vs Facets:")
        for facet_addr, slot, mask, conflict_type, detail_1, detail_2 in diamond_storage_conflicts_detail_list:
            report_lines.append(f"    - Facet {facet_addr} → Slot {slot} Mask {mask} → {conflict_type} ({detail_1} vs {detail_2})")
    else:
        report_lines.append("- Proxy vs Logic:")
        for slot, mask, conflict_type, detail_1, detail_2 in storage_conflicts_detail_list:
            report_lines.append(f"    - Slot {slot} Mask {mask} → {conflict_type} ({detail_1} vs {detail_2})")
    report_lines.append("\n---\n")

    # 3️ Initialization Missing
    report_lines.append("## 3. Initialization Missing Check")

    if if_initialization_missing:
        report_lines.append("- Initialization Status: **NOT INITIALIZED**")
        report_lines.append(f"- Suggested Action: Call the initialize function {uninitialized_slots_detail_list[0][1]} to complete initialization.")
    else:
        report_lines.append("- Initialization Status: INITIALIZED")


    report_lines.append("\n---\n")

    # 4️ Permission Control
    report_lines.append("## 4. Permission Control Analysis")

    report_lines.append("- Sensitive Storage Slots:")
    for var_name, slot_id, mask in sensitive_slots_detail_list:
        report_lines.append(f"    - {var_name} → Slot {slot_id} Mask {mask}")

    report_lines.append("- Detected Permission Check Locations:")
    for selector, check_status, details in permission_check_summary:
        report_lines.append(f"    - Selector {selector} → {check_status} → {details}")
    report_lines.append("\n---\n")

    # 5️ Final Assessment
    report_lines.append("## 5. Final Assessment")
    overall_posture = "Needs Improvement" if (
        if_selectors_collide or has_conflict or if_initialization_missing or has_permission_missing
    ) else "Good"
    recommendation = "Needs fixes" if overall_posture != "Good" else "Safe to deploy"

    report_lines.append(f"**Overall Security Posture**: {overall_posture}")
    report_lines.append(f"**Recommendation**: {recommendation}")
    report_lines.append("\n---\n")

    return "\n".join(report_lines)


def extract_selector_and_impl_from_logic(explorer, contract_address,bytecode):
    """
    Extract all function selectors from a logic contract behind a proxy via fallback delegatecall.
    
    Args:
        explorer (EthereumExplorerRPC): Blockchain explorer.
        bytecode (str): Bytecode of the proxy contract.
        contract_address (str): Address of the proxy.
        owner (str): Address used as caller for simulation (msg.sender).
    
    Returns:
        set[str]: Set of function selectors from the logic contract (e.g. {"0xa9059cbb", ...}).
    """
    bytecode_selectors = None
    logic_address = None
    code_size = len(bytecode[2:]) // 2
    try:
        fallback_selector = "0xaabbccdd"
        calldata = bytes.fromhex(fallback_selector[2:] + "00" * 32)

        callinfo = {
            'calldata': calldata,
            'callvalue': 0,
            'origin_proxy':contract_address,
            'address': contract_address,
            'codesize': code_size,
            'storage_address': contract_address,
            'owner_slot': 0,
            'caller': "0x" + "cc" * 20,
            'origin': "0x" + "cc" * 20
        }

        state = EthereumVMstate(explorer)
        emul = EthereumSSAEngine(bytecode, explorer)
        emul.emulate(callinfo.copy(), state, debug=False,if_storage_analysis=False)
        info = emul.get_delegate_info()

        if not info:
            # print(f"[X] No delegatecall target found via fallback simulation.")
            return bytecode_selectors,logic_address

        logic_address = info[0].get("address")
        if logic_address is None:
            # print(f"[X] Delegatecall address not found in fallback info.")
            return bytecode_selectors,logic_address

        # print(f"[✓] Logic contract address from fallback delegatecall: {logic_address}")

        bytecode_logic = explorer.eth_getCode(logic_address)
        bytecode_selectors = extract_selectors_from_bytecode(bytecode_logic)

        return bytecode_selectors,logic_address

    except Exception as e:
        # print(f"[X] Exception during logic selector extraction: {e}")
        return bytecode_selectors,logic_address

def extract_selectors_from_bytecode(bytecode):
    disasm = EthereumDisassembler(bytecode)
    instrs = disasm.disassemble()
    selectors = set()
    for instr in instrs:
        if instr.name == 'PUSH4':
            selectors.add(f"{instr.operand_interpretation:#0{10}x}")
    selectors.discard("0xffffffff")
    return selectors

def diamond_selector_map_with_facets(explorer, contract_address):
    """
    Attempt to call facets() to determine if this is a Diamond contract.
    Supports both EIP-2535 (address,bytes4[])[] and (address[],bytes4[][]) formats.

    Returns:
        selector_map: dict(selector -> facet_address)
        facet_addresses: set of facet addresses
        is_diamond: bool indicating whether the contract is a Diamond proxy
    """
    selector_map = {}
    facet_addresses = set()
    is_diamond = False  # Default to not a Diamond

    facets_selector = "0x7a0ed627"
    calldata = bytes.fromhex(facets_selector[2:])
    try:
        result = explorer.eth_call(to_address=contract_address, data="0x" + calldata.hex())
        if not result or result in ("0x", "0x0"):
            return selector_map, facet_addresses, False  # facets() not implemented or returned empty

        data = bytes.fromhex(result[2:])
        codec = ABICodec(registry)

        try:
            # 尝试 EIP-2535 标准格式：[(address, bytes4[])]
            decoded = codec.decode(["(address,bytes4[])[]"], data)[0]
            is_diamond = True
            for facet in decoded:
                facet_addr = facet[0]
                facet_addresses.add(facet_addr)
                for sel in facet[1]:
                    selector_map["0x" + sel.hex()] = facet_addr
        except:
            # 退而求其次格式：(address[], bytes4[][])
            decoded = codec.decode(["address[]", "bytes4[][]"], data)
            is_diamond = True
            facet_addrs, selectors_list = decoded
            for addr, sels in zip(facet_addrs, selectors_list):
                facet_addresses.add(addr)
                for sel in sels:
                    selector_map["0x" + sel.hex()] = addr
    except Exception as e:
        pass
        # # print(f"[!] Failed to decode diamond facets result: {e}")
    # # print(f"[+] Detected {len(selector_map)} selectors from diamond facets.")
    return selector_map, facet_addresses, is_diamond


def extract_delegatecall_slot(contract_address, bytecode, owner, is_diamond, diamond_selectors, delegatecall_addr, explorer, verbose=False):
    """
    Extract delegatecall slot mappings from a proxy contract.

    Returns:
        dict[str, list[tuple[str, int]]]: {
            logic_contract_address: [(proxy_contract_address, storage_slot), ...]
        }
    """
    merged_delegatecall_slot_map = {}
    code_size = len(bytecode[2:]) // 2

    # Prepare selectors
    if not is_diamond:
        fallback_selector = "0xaabbccdd"
        while fallback_selector in diamond_selectors:
            fallback_selector = f"0x{int(fallback_selector, 16) + 1:08x}"
        selectors_to_test = {fallback_selector: None}
    else:
        selectors_to_test = {s: None for s in diamond_selectors} if isinstance(diamond_selectors, set) else diamond_selectors

    i=0
    for selector, _ in sorted(selectors_to_test.items()):
        calldata = bytes.fromhex(selector[2:] + "00" * 128)
        callinfo = {
            'calldata': calldata,
            'callvalue': 0,
            'origin_proxy':contract_address,
            'address': contract_address,
            'codesize': code_size,
            'storage_address': contract_address,
            'delegatecall_addr': delegatecall_addr,  # dict[str, bool]
            'delegatecall_slot_map':{},
            'owner_slot': 0,
            'caller': owner,
            'origin': owner
        }

        state = EthereumVMstate(explorer)
        emul = EthereumSSAEngine(bytecode, explorer)
        emul.emulate(callinfo.copy(), state, debug=False,if_storage_analysis=False)

        current_map = emul.result.get("delegatecall_slot_map", {})
        for logic_addr, pair in current_map.items():
            if isinstance(pair, tuple) and len(pair) == 2:
                # # print(f"processing {pair}")
                if logic_addr not in merged_delegatecall_slot_map:
                    merged_delegatecall_slot_map[logic_addr] = pair
                    proxy_addr, slot = pair
                    print(f"[√] [#{i} Logic Address]:{logic_addr}")
                    if len(merged_delegatecall_slot_map) == len(delegatecall_addr):
                        return merged_delegatecall_slot_map
                    i =  i+1
    return merged_delegatecall_slot_map

def extract_owner(contract_address,bytecode, selectors, delegatecall_addr,explorer, verbose=False):
    """
    Attempt to retrieve the owner/admin address using multiple strategies:
    1. First, try calling 'owner()' directly.
    2. If it fails, try calling 'admin()' instead.
    3. If both fail, simulate execution and look for CALLER == SLOAD(...) patterns.
    """

    contract_owner = None
    owner_slot = None
    owner_mask = None
    code_size = len(bytecode[2:]) // 2
    fallback_selector = {"0xffffffff"}
    selectors = selectors.union(fallback_selector)
    owner_val = "0x" + "cc" * 20

    test_selector = {"0x3659cfe6"}  #selector of function upgradeto()

    for selector in selectors:
        calldata = bytes.fromhex(selector[2:] + "00"*128)
        callinfo = {
            'calldata': calldata,
            'callvalue': 0,
            'origin_proxy':contract_address,
            'address': contract_address,
            'codesize': code_size,
            'storage_address': contract_address,
            'delegatecall_addr': delegatecall_addr,
            "delegatecall_slot_map":{},
            'owner_slot': 0,
            'caller': "0x" + "cc" * 20,
            'origin': "0x" + "cc" * 20
        }

        state = EthereumVMstate(explorer)
        emul = EthereumSSAEngine(bytecode, explorer)
        emul.emulate(callinfo.copy(), state, debug=False,if_storage_analysis=False)
        slot_usage = emul.get_slot_usage()
        slot_usage_log = order_slot_usages(slot_usage,{})
        owner = emul.result.get('owner')
        for slot,subslots in slot_usage_log.items():
            subslots = subslots.get("subslots")
            for mask,entry in subslots.items():
                opcodes = entry.get("opcodes",None)
                if opcodes:
                    EQ = opcodes.get("EQ", None)
                    if EQ:
                        for global_entry in EQ:
                            caller_tag = global_entry.get("tag", "None") if isinstance(global_entry, dict) else "None"
                            if caller_tag.lower() == "caller":
                                owner_slot = slot
                                owner_mask = mask
                                # Attempt to detect owner-like value from execution result
                                owner_val = emul.result.get('owner')
                                if isinstance(owner_val, int):
                                    # Normalize address
                                    addr_int = owner_val & ((1 << 160) - 1)
                                    contract_owner = "0x" + hex(addr_int)[2:].rjust(40, '0')
                                    print(f"[√] [Owner address]: {contract_owner}")
                                    return contract_owner,owner_slot,owner_mask
    print(f"[!] Failed to detect owner address from simulation.")
    return contract_owner,owner_slot,owner_mask


def extract_beacon_selectors(contract_address, bytecode,delegatecall_addr,explorer, verbose=False):
    """
    Attempt to retrieve the beacon address using multiple strategies:
    1. First, try calling 'beacon()' directly.
    2. If it fails, try calling 'getBeacon()' instead.
    3. If both fail, simulate execution
    """
    code_size = len(bytecode[2:]) // 2
    selectors_from_beacon = set()
    beacon_addr = None
    calldata = bytes.fromhex("ffffffff" + "00"*128)

    fallback_callinfo = {
        'calldata': calldata,
        'callvalue': 0,
        'origin_proxy':contract_address,
        'address': contract_address,
        'codesize': code_size,
        'storage_address': contract_address,
        'delegatecall_addr': delegatecall_addr,
        'owner_slot': 0,
        'delegatecall_slot_map':{},
        'caller': "0x" + "cc" * 20,
        'origin': "0x" + "cc" * 20
    }

    fallback_state = EthereumVMstate(explorer)
    fallback_emul = EthereumSSAEngine(bytecode, explorer)
    fallback_emul.emulate(fallback_callinfo.copy(), fallback_state, debug=False,if_storage_analysis=False)    
    
    beacon_addr = fallback_emul.result.get('beacon_addr')
    # print(f"[+] [beacon matching] Found potential beacon address: {beacon_addr}")

    if beacon_addr is None:
        return selectors_from_beacon,None, None, False

    # 2.obtain beacon bytecode and ABI
    beacon_bytecode = explorer.eth_getCode(beacon_addr)

    # 3. extract selector
    try:
        selectors_from_bytecode = extract_selectors_from_bytecode(beacon_bytecode)
        selectors_from_beacon = set(selectors_from_bytecode) 
    except Exception as e:
        # print(f"[X] Failed to extract selectors from beacon: {e}")
        selectors_from_beacon = set()

    # print(f"[+] Detected {len(selectors_from_beacon)} selectors from beacon contract.")
    is_beacon = len(selectors_from_beacon) > 0
    return selectors_from_beacon, beacon_addr, beacon_bytecode,is_beacon
        

def extract_base_slot(slot_id):
    """Ensure slot_id is string before regex matching."""
    slot_str = str(slot_id)
    match = re.match(r"^([0-9a-fA-Fx]+)", slot_str)
    return match.group(1) if match else slot_str

def analyze_contract_storage( address, selectors, explorer, caller=None):
    print(f"[+] Trying to analyze Storage Layout of contract {address}")
    bytecode = explorer.eth_getCode(address)
    code_size = len(bytecode[2:]) // 2
    slot_profile = {}
    global_slot_usage = {}
    fallback_selector = "0xaabbccdd"
    selectors = selectors.union({fallback_selector})
    test_selectors = set()

    test_selectors = {"0x02fc24a9"}  # selector of mapping(bytes4 => FacetAddressAndPosition) struct {address facetAddress;uint96 functionSelectorPosition;}
    test_selectors = {"0x02fc24a9"}  # selector of mapping(address => FacetFunctionSelectors) struct {bytes4[] functionSelectors;uint256 facetAddressPosition;}
    # test_selectors = {"0xc3734b7b"}  # selector1 of uint256[][]
    # test_selectors = test_selectors.union({"0x54058a4b"})  # selector2 of uint256[][]
    # test_selectors = {"0xf36b716a"}  # selector of mapping(address => mapping(bytes32 => RoleData)) struct RoleData {mapping(address => bool) members;bytes32 adminRole;}


    for selector in sorted(selectors):
        # # print(f"[+] Analyzing selector {selector}...")
        state = EthereumVMstate(explorer)
        calldata = bytes.fromhex(selector[2:] + "00" * 128)
        callinfo = {
            'calldata': calldata,
            'callvalue': 0,
            'address': address,
            'codesize': len(bytecode),
            'storage_address': address,
            'delegatecall_slot_map':{},
            'caller': caller,
            'origin': caller,
        }

        emul = EthereumSSAEngine(bytecode, explorer)
        emul.emulate(callinfo.copy(), state, debug=False,if_storage_analysis=True)
        slot_usage = emul.get_slot_usage()
        global_slot_usage = order_slot_usages(slot_usage,global_slot_usage)


    global_slot_usage,slot_profile = analyze_slot_types(global_slot_usage)

    # print("global slot_usage:")
    # print(json.dumps(global_slot_usage, indent=4))

    # # print("[+] Slot profile:")
    # # print(json.dumps(slot_profile, indent=4))

    return global_slot_usage,slot_profile


def order_slot_usages(slot_usage,global_slot_usage):
    for slot_id, usage in slot_usage.items():
            base_slot = extract_base_slot(slot_id)

            # Ensure base entry exists
            if base_slot not in global_slot_usage:
                global_slot_usage[base_slot] = {"subslots": {}}
            mask = compute_mask_from_ops(str(slot_id))

            # Prepare subslot dict under mask key
            global_slot_usage[base_slot]["subslots"].setdefault(mask, {
                "opcodes": {},
                "write_from": [],
                "source": []
            })

            if isinstance(usage, list):
                for entry in usage:
                    op = entry.get("used_in")
                    if op:
                        global_slot_usage[base_slot]["subslots"][mask]["opcodes"].setdefault(op, []).append(entry.get("with"))

                    if "write_from" in entry:
                        wf = entry["write_from"]
                        if wf not in global_slot_usage[base_slot]["subslots"][mask]["write_from"]:
                            global_slot_usage[base_slot]["subslots"][mask]["write_from"].append(wf)

                    if "source" in entry:
                        src = entry["source"]
                        if src not in global_slot_usage[base_slot]["subslots"][mask]["source"]:
                            global_slot_usage[base_slot]["subslots"][mask]["source"].append(src)
    return global_slot_usage

def analyze_slot_types(slot_usage):
    address_related_tags = {"origin", "caller", "address"}
    bool_related_opcodes = {"ISZERO", "EQ", "NE"}
    uint_related_opcodes = {"ADD", "SUB", "MUL", "DIV", "GT", "LT", "GE", "LE"}
    address_opcodes = {"OR", "AND", "EQ"}
    call_opcodes = {'CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'}
    byte_opcodes = {"AND", "OR", "XOR", "BYTE"}

    result = {}
    dependency_map = {}  # (slot, mask) → source_tag (SLOAD_SLOT_X)
    slot_type_map = {}   # (slot, mask) → typ

    # Pass 1: normal infer + record dependencies
    for slot, slot_data in slot_usage.items():
        subslots = slot_data.get("subslots", {})
        result[slot] = {}
        for mask, subslot_data in subslots.items():
            opcodes = subslot_data.get("opcodes", {})
            write_froms = subslot_data.get("write_from", [])

            # === Skip subslots that only have OR (likely SSTORE packing)
            op_list = set(opcodes.keys())
            if op_list == {"OR"}:
                # print(f"[Skip] Slot {slot} Subslot {mask} only has OR opcodes → skip as likely SSTORE packing")
                continue

            # === juge if there is write events for multiple variables in same slot
            if len(subslots) >= 2 and mask.lower() == "0x" + "ff" * 32:
                and_ops = opcodes.get("AND", [])
                source = subslot_data.get("source",[])
                VALID_FIELD_BYTES = {1, 2, 4, 8, 12,16, 20, 32}

                for _mask, _subslot_data in subslots.items():
                    if _mask != mask:
                        slot_usage[slot]["subslots"][_mask]["source"] = source[:]

                for and_entry in and_ops:
                    val_hex = and_entry.get("val")
                    if val_hex is None:
                        continue

                    val_int = int(val_hex, 16)
                    inverted = (~val_int) & ((1 << 256) -1)  
                    inverted_bin = bin(inverted)[2:].zfill(256)

                    if re.fullmatch(r'0*1*0*', inverted_bin) or re.fullmatch(r'1*0*1*', inverted_bin):
                        ones = inverted_bin.count('1')
                        field_bytes = ones // 8
                        if ones % 8 != 0:
                            continue  

                        if field_bytes in VALID_FIELD_BYTES:
                            field_mask_hex = hex(inverted)[2:].zfill(64)
                            field_mask_hex = "0x" + field_mask_hex  

                            if field_mask_hex.lower() == "0x" + "ff" * 32:
                                continue
                            result[slot][field_mask_hex] = {
                                "type": "unknown",
                                "writable": True
                            }
                continue

            # === Run normal infer logic
            inferred_type = infer_slot_type(
                mask,
                opcodes,
                address_related_tags,
                bool_related_opcodes,
                uint_related_opcodes,
                address_opcodes,
                call_opcodes,
                byte_opcodes
            )
            # === Determine writable flag
            is_writable = bool(write_froms)
            prev_writable = result[slot].get(mask, {}).get("writable", False)

            if inferred_type == "unknown" and write_froms:
                for wf in write_froms:
                    src_tag = wf.get("tag", "").lower()
                    if src_tag in address_related_tags:
                        inferred_type = "address"
                        break
                    elif src_tag.startswith("sload_slot_"):
                        dependency_map[(slot, mask)] = src_tag
                        break
                    elif src_tag == "bool":  
                        inferred_type = "bool"
                        break

            slot_type_map[(slot, mask)] = inferred_type
            result[slot][mask] = {
                "type": inferred_type,
                "writable": is_writable or prev_writable
            }

    # Pass 2: resolve dependencies
    changed = True
    while changed:
        changed = False
        for (slot, mask), dep_tag in dependency_map.items():
            if slot_type_map[(slot, mask)] == "unknown":
                dep_slot_match = re.match(r"sload_slot_([0-9a-fA-Fx]+)", dep_tag)
                if dep_slot_match:
                    dep_slot_base = dep_slot_match.group(1)
                    dep_slot = str(int(dep_slot_base, 16 if dep_slot_base.startswith("0x") else 10))
                    dep_mask = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  # full mask slot
                    dep_type = slot_type_map.get((dep_slot, dep_mask), "unknown")

                    if dep_type != "unknown":
                        # print(f"[Pass2] Resolving slot {slot} mask {mask} from source slot {dep_slot} → type {dep_type}")
                        slot_type_map[(slot, mask)] = dep_type
                        result[slot][mask]["type"] = dep_type
                        changed = True

    # # print("[+] Slot profile:")
    # # print(json.dumps(result, indent=4))
    merge_array_bytes_mapping_slots(result,slot_usage)
    return slot_usage,result


def compute_mask_from_ops(slot_id: str):
    FULL_MASK = (1 << 256) - 1
    current_mask = FULL_MASK

    # Extract masks from AND first
    and_masks = [int(m, 16) for m in re.findall(r"AND\((0x[0-9a-fA-F]+)\)", slot_id)]
    for m in and_masks:
        current_mask &= m

    # Apply DIV (which should result in left shift)
    div_matches = re.findall(r"DIV\((0x[0-9a-fA-F]+)\)", slot_id)
    for d_hex in div_matches:
        d = int(d_hex, 16)
        if d == 0:
            continue
        if d & (d - 1) == 0:
            shift = d.bit_length() - 1
            current_mask = (current_mask << shift) & FULL_MASK

    # Apply MUL(which should result in right shift)
    mul_matches = re.findall(r"MUL\((0x[0-9a-fA-F]+)\)", slot_id)
    for m_hex in mul_matches:
        m = int(m_hex, 16)
        if m == 0:
            continue
        if m & (m - 1) == 0:
            shift = m.bit_length() - 1
            current_mask >>= shift

    # Apply SHR (still left shift)
    shr_matches = re.findall(r"SHR\((0x[0-9a-fA-F]+)\)", slot_id)
    for s_hex in shr_matches:
        s = int(s_hex, 16)
        current_mask = (current_mask << s) & FULL_MASK

    # Apply SHL (should be RIGHT SHIFT)
    shl_matches = re.findall(r"SHL\((0x[0-9a-fA-F]+)\)", slot_id)
    for s_hex in shl_matches:
        s = int(s_hex, 16)
        current_mask >>= s

    # Apply BYTE
    byte_match = re.search(r"BYTE\((\d+)\)", slot_id)
    if byte_match:
        offset = int(byte_match.group(1))
        if 0 <= offset < 32:
            byte_mask = 0xff << (8 * (31 - offset))
            current_mask &= byte_mask


    hex_mask = f"0x{current_mask:064x}"
    return hex_mask


def infer_slot_type(mask: str, opcodes: dict, address_related_tags, 
                    bool_related_opcodes, uint_related_opcodes, 
                    address_opcodes, call_opcodes,byte_opcodes):
    inferred_type = "unknown"

    for op, operands in opcodes.items():
        if op in call_opcodes:
            inferred_type = "address"
            break
        if op in address_opcodes:
            for o in operands:
                tag = o.get("tag", "").lower()
                if any(a in tag for a in address_related_tags):
                    inferred_type = "address"
                    break
            if inferred_type == "address":
                break
        if op in bool_related_opcodes:
            is_bool_pattern = True
            if op in ["EQ","NE"]:
                for o in operands:
                    val = o.get("val")
                    if isinstance(val, str):
                        val = int(val, 16)
                    if val not in (0x00, 0x01):
                        is_bool_pattern = False
                        break
            if is_bool_pattern:
                inferred_type = "bool"
                break
        if op in byte_opcodes:
            inferred_type = "bytes"
            break
        if op in uint_related_opcodes:
            if op == "SUB":
                for o in operands:
                    tag = o.get("tag", "").lower()
                    if any(a in tag for a in address_related_tags):
                        inferred_type = "address"
                        break
                if inferred_type == "address":
                    break
            inferred_type = "uint"
            break


    # Post-processing if uint → figure out uintN / address / uint160
    if inferred_type == "uint":
        bit_count = bin(int(mask, 16)).count("1")
        if bit_count == 160:
            is_address_related = False
            for op2, operands2 in opcodes.items():
                if op2 in address_opcodes:
                    for o in operands2:
                        tag = o.get("tag", "").lower()
                        if any(a in tag for a in address_related_tags):
                            is_address_related = True
                            break
            if is_address_related:
                inferred_type = "address"
            else:
                inferred_type = "uint160"
        else:
            if bit_count <= 8:
                inferred_type = "uint8"
            elif bit_count <= 16:
                inferred_type = "uint16"
            elif bit_count <= 32:
                inferred_type = "uint32"
            elif bit_count <= 64:
                inferred_type = "uint64"
            elif bit_count <= 128:
                inferred_type = "uint128"
            else:
                inferred_type = "uint256"

    return inferred_type

def nesting_depth(type_str):
    # Count the nesting level by counting array and mapping keywords
    return type_str.count("[]") + type_str.count("mapping")

def merge_array_bytes_mapping_slots(result, slot_usage): 
    derived_slot_map = {}
    base_slot_type_map = {}
    base_slot_tag = {}

    for slot, slot_data in slot_usage.items():
        slot_str = str(slot)
        subslots = slot_data.get("subslots", {})
        for mask, subslot_data in subslots.items():
            for source_entry in subslot_data.get("source", []):
                tag = source_entry.get("tag", "")
                if "sha3(" in tag.lower():
                    base_slot, structure = parse_nested_sha3_tag(tag)
                    base_slot_str = str(base_slot)
                    derived_slot_map.setdefault(base_slot_str, set()).add(slot_str)

                    # Compare nesting depth before overwriting
                    existing_structure = base_slot_type_map.get(base_slot_str)
                    if existing_structure is None or nesting_depth(structure) > nesting_depth(existing_structure):
                        base_slot_type_map[base_slot_str] = structure
                        base_slot_tag[base_slot_str] = tag


    for base_slot, derived_slots in derived_slot_map.items():
        subslot_entries = {}  
        for derived_slot in derived_slots:
            slot_info = slot_usage.get(derived_slot, {})
            subslots = slot_info.get("subslots",{})
            if len(subslots) == 1:
                for mask, mask_entry in subslots.items():
                    _type = result.get(derived_slot, {}).get(mask, {}).get("type", "unknown")
                    base_tag = base_slot_tag.get(base_slot)
                    _,final_type = parse_nested_sha3_tag(base_tag,_type)
                    _writable = result.get(derived_slot, {}).get(mask, {}).get("writable", False)
                    subslot_entries[mask] = {
                        "type": final_type,
                        "writable": _writable
                    }
            else:
                for mask, mask_entry in subslots.items():
                    if mask.lower() == "0x" + "ff" * 32:
                        continue
                    _type = result.get(derived_slot, {}).get(mask, {}).get("type", "unknown")
                    base_tag = base_slot_tag.get(base_slot)
                    _,final_type = parse_nested_sha3_tag(base_tag,_type)
                    _writable = result.get(derived_slot, {}).get(mask, {}).get("writable", False)
                    subslot_entries[mask] = {
                        "type": final_type,
                        "writable": _writable
                    }

        if subslot_entries:
            result[base_slot] = subslot_entries

        for derived_slot in derived_slots:
            result.pop(derived_slot, None)

    return result



def merge_slot_profiles(*slot_profiles):
    """
    Merge multiple slot_profile dicts into a unified merged_slot_profile.

    Args:
        *slot_profiles: any number of slot_profile dicts

    Returns:
        merged_slot_profile: dict
    """
    merged_slot_profile = {}

    # First pass: detect which slots already have known types
    slot_known_types = {}

    for slot_profile in slot_profiles:
        for slot, mask_info in slot_profile.items():
            for mask, info in mask_info.items():
                typ = info.get("type", "unknown")
                if typ != "unknown":
                    slot_known_types[slot] = True  # This slot has at least one known type

    # Second pass: do merging with awareness of known type existence
    for slot_profile in slot_profiles:
        for slot, mask_info in slot_profile.items():
            if slot not in merged_slot_profile:
                merged_slot_profile[slot] = {}

            for mask, info in mask_info.items():
                new_type = info.get("type", "unknown")

                # Skip unknown masks if slot already has known types
                if new_type == "unknown" and slot_known_types.get(slot, False):
                    continue  # skip

                existing_info = merged_slot_profile[slot].get(mask, {})
                existing_type = existing_info.get("type", None)

                # Merge type logic
                if existing_type is None:
                    merged_type = new_type
                elif existing_type == new_type:
                    merged_type = existing_type
                elif existing_type != "unknown" and new_type == "unknown":
                    merged_type = existing_type
                elif existing_type == "unknown" and new_type != "unknown":
                    merged_type = new_type
                else:
                    merged_type = f"conflict: {existing_type} | {new_type}"

                # Merge writable
                existing_writable = existing_info.get("writable", False)
                new_writable = info.get("writable", False)
                merged_writable = existing_writable or new_writable

                # Update
                merged_slot_profile[slot][mask] = {
                    "type": merged_type,
                    "writable": merged_writable
                }

    # # print(f"merged_slot_profile:{merged_slot_profile}")
    return merged_slot_profile

def merge_global_slot_usages(*global_usages):
    merged = {}

    for usage in global_usages:
        for slot, slot_entry in usage.items():
            if slot not in merged:
                merged[slot] = {"subslots": {}}

            subslots = slot_entry.get("subslots", {})
            merged_subslots = merged[slot]["subslots"]

            for mask, entry in subslots.items():
                if mask not in merged_subslots:
                    # First time adding this mask
                    merged_subslots[mask] = {
                        "opcodes": entry.get("opcodes", {}).copy(),
                        "write_from": list(entry.get("write_from", [])),
                        "source": list(entry.get("source", []))
                    }
                else:
                    # Merge opcodes
                    existing_opcodes = merged_subslots[mask]["opcodes"]
                    new_opcodes = entry.get("opcodes", {})

                    for op, op_entry in new_opcodes.items():
                        if op not in existing_opcodes:
                            existing_opcodes[op] = op_entry
                        else:
                            # If existing entry is list, merge lists
                            if isinstance(existing_opcodes[op], list) and isinstance(op_entry, list):
                                for item in op_entry:
                                    if item not in existing_opcodes[op]:
                                        existing_opcodes[op].append(item)
                            else:
                                # Otherwise, just overwrite (safe fallback)
                                existing_opcodes[op] = op_entry

                    # Merge write_from → list of dicts → safe merge
                    existing_write_from = merged_subslots[mask]["write_from"]
                    new_write_from = entry.get("write_from", [])

                    for item in new_write_from:
                        if item not in existing_write_from:
                            existing_write_from.append(item)

                    # Merge source (list merge + dedup by tag)
                    existing_sources = merged_subslots[mask]["source"]
                    new_sources = entry.get("source", [])

                    # To avoid duplicate dicts, merge by 'tag' field
                    existing_tags = set(src.get("tag") for src in existing_sources if "tag" in src)
                    for src in new_sources:
                        tag = src.get("tag")
                        if tag not in existing_tags:
                            existing_sources.append(src)
                            existing_tags.add(tag)

    return merged



import re

def parse_nested_sha3_tag(tag_str, inferred_type=None):

    def recursive_parse(tag, current_type):
        mapping_pattern = r"^SHA3\(Mapping,selector=0x[0-9a-fA-F]+,Mapping_slot=(.+)\)$"
        array_pattern = r"^SHA3\(Array, ?Base_slot=(.+)\)$"

        if re.fullmatch(r"\d+", tag):
            return int(tag), current_type or "unknown"

        mapping_match = re.match(mapping_pattern, tag)
        if mapping_match:
            inner = mapping_match.group(1)
            base_slot, inner_type = recursive_parse(inner.strip(), current_type)
            return base_slot, f"mapping(unknown => {inner_type})"

        array_match = re.match(array_pattern, tag)
        if array_match:
            inner = array_match.group(1)
            base_slot, inner_type = recursive_parse(inner.strip(), current_type)
            return base_slot, f"{inner_type}[]"

        return -1, current_type or "unknown"

    return recursive_parse(tag_str, inferred_type)



def detect_upgrade_function(contract_address, bytecode, owner, owner_slot, owner_mask, delegatecall_slot_map, selectors, explorer):
    print(f"[+] Checking if upgrade function exists in contract {contract_address}...")
    code_size = len(bytecode[2:]) // 2
    has_upgrade_function = False

    for selector in sorted(selectors):
        calldata = bytes.fromhex(selector[2:] + "00" * 12 + "ee" * 20)
        callinfo = {
            'calldata': calldata,
            'callvalue': 0,
            'origin_proxy': contract_address,
            'address': contract_address,
            'codesize': code_size,
            'storage_address': contract_address,
            'owner_slot': owner_slot,
            'owner_mask': owner_mask,
            'delegatecall_slot_map': delegatecall_slot_map,
            'caller': owner,
            'origin': owner
        }

        state = EthereumVMstate(explorer)
        emul = EthereumSSAEngine(bytecode, explorer)
        emul.emulate(callinfo.copy(), state, debug=False, if_storage_analysis=False)

        if emul.result.get('write_owner') or emul.result.get("delegate_overwrite"):
            has_upgrade_function = True
            break  

    return has_upgrade_function

def extract_impl_slot_from_delegatecall_slot_map(delegatecall_slot_map, is_diamond):
    if is_diamond:
        return None

    for _, (_, slot) in delegatecall_slot_map.items():
        return slot  
    return None