from tools.utils import order_slot_usages 

from octopus.platforms.ETH.vmstate import EthereumVMstate
from octopus.platforms.ETH.emulator import EthereumSSAEngine


def check_storage_conflict(slot_profile_1, slot_profile_2, is_logic_to_logic_conflict=False):
    """
    Check if two slot profiles have storage conflicts.

    Args:
        slot_profile_1 (dict): slot profile of source contract (proxy+logic or logic V1).
        slot_profile_2 (dict): slot profile of target contract (new logic or logic V2).
        is_logic_to_logic_conflict (bool): True if comparing logic V1 → V2 (writable change counts as conflict);
                                           False if comparing proxy → logic (writable change not counted as conflict).

    Returns:
        (bool, list): (True if storage conflicts detected, False otherwise), List of (slot, mask, conflict_type, detail_1, detail_2)
    """
    has_conflict = False
    conflict_details = []

    # Iterate over slots in both profiles
    all_slots = set(slot_profile_1.keys()).intersection(set(slot_profile_2.keys()))

    for slot in sorted(all_slots, key=lambda x: int(x)):
        subslots_1 = slot_profile_1[slot]
        subslots_2 = slot_profile_2[slot]

        all_masks = set(subslots_1.keys()).union(set(subslots_2.keys()))

        for mask in sorted(all_masks):
            entry_1 = subslots_1.get(mask)
            entry_2 = subslots_2.get(mask)

            if entry_1 and entry_2:
                # Both sides have this slot+mask → compare type & writable
                type_1 = entry_1.get("type", "unknown")
                type_2 = entry_2.get("type", "unknown")
                writable_1 = entry_1.get("writable", False)
                writable_2 = entry_2.get("writable", False)

                # Type conflict
                if type_1 != type_2:
                    # print(f"[!] Type conflict at slot {slot} mask {mask}: {type_1} vs {type_2}")
                    conflict_details.append((slot, mask, "type", type_1, type_2))
                    has_conflict = True

                # Writable conflict → only if logic-to-logic comparison
                elif is_logic_to_logic_conflict and writable_1 != writable_2:
                    # print(f"[!] Writable conflict at slot {slot} mask {mask}: writable {writable_1} vs {writable_2}")
                    conflict_details.append((slot, mask, "writable", writable_1, writable_2))
                    has_conflict = True

            elif entry_1 and not entry_2:
                # Mask disappeared → conflict
                # print(f"[!] Mask disappeared at slot {slot} mask {mask} → present in source, missing in target.")
                conflict_details.append((slot, mask, "mask disappeared", None, None))
                has_conflict = True

            elif not entry_1 and entry_2:
                # Mask newly added → conflict
                # print(f"[!] New mask appeared at slot {slot} mask {mask} → missing in source, present in target.")
                conflict_details.append((slot, mask, "mask added", None, None))
                has_conflict = True

    # if not has_conflict:
    #     # print("[+] No storage conflicts detected.")
    # else:
    #     # print(f"[+] Summary: {len(conflict_details)} conflict(s) detected.")

    return has_conflict, conflict_details



def check_if_selector_collides(proxy_address, proxy_selectors, logic_selectors_set, is_diamond=False, selectors_from_diamond=None):
    """
    Check for function selector collisions between proxy and logic contracts (including diamond facets).

    Args:
        proxy_address (str): Address of the proxy contract (hex string, lowercased).
        proxy_selectors (set): Set of selectors present in proxy.
        logic_selectors_set (set): Set of selectors from logic contract.
        is_diamond (bool): Whether it's a diamond contract.
        selectors_from_diamond (dict): {selector -> facet_address}, only for diamond (optional).

    Returns:
        (bool, list): (True if collision(s) detected, False otherwise), List of (selector, location) pairs
    """
    print("[+] Trying to check if Selector Collides")
    if_collides = False
    collision_selectors_detail = []

    # Non-diamond pattern
    if not is_diamond:
        for selector in logic_selectors_set:
            if selector in proxy_selectors:
                # print(f"[!] WARNING: Selector collision detected with logic contract: {selector}")
                collision_selectors_detail.append((selector, "logic"))
                if_collides = True

    # Diamond pattern
    elif selectors_from_diamond is not None:
        # 1. facet_addr -> set(selectors), only for selectors already present in facets
        from collections import defaultdict
        facet_selectors_map = defaultdict(set)
        for selector, facet_addr in selectors_from_diamond.items():
            facet_selectors_map[facet_addr.lower()].add(selector)  # normalize address to lowercase

        # 2. For each facet (excluding proxy_address itself), check collisions
        for facet_addr, selectors in facet_selectors_map.items():
            if facet_addr == proxy_address.lower():
                continue  # skip proxy self-calls, not considered collision
            for selector in selectors:
                if selector in proxy_selectors:
                    # print(f"[!] WARNING: Selector collision between proxy and facet {facet_addr}: {selector}")
                    collision_selectors_detail.append((selector, f"facet {facet_addr}"))
                    if_collides = True

    # Summary
    # if if_collides:
    #     # print(f"[+] Summary: Detected selector collisions:")
    #     for selector, location in collision_selectors_detail:
    #         # print(f"    - {selector} → {location}")
    # else:
    #     # print("[+] No selector collisions detected.")

    return if_collides, collision_selectors_detail

def check_Missing_Initialization(contract_address, bytecode, slot_profile, selectors, logic_global_slot_usage, explorer):
    print(f"[+] Initialization Missing Check on contract {contract_address} with {len(selectors)} selectors")
    code_size = len(bytecode[2:]) // 2
    fallback_selector = "0xaabbccdd"
    selectors = selectors.union({fallback_selector})

    current_selector_usage = {}
    found_initialization_pattern = False
    test_selector = {"0x8129fc1c"}

    initialize_slot = None
    initialize_mask = None
    owner_mask = None
    owner_slot = None
    initialize_flag = False
    owner_flag = False

    # === prepare uninitialized_slots_detail_list ===
    uninitialized_slots_detail_list = []

    for selector in sorted(selectors):
        state = EthereumVMstate(explorer)
        calldata = bytes.fromhex(selector[2:] + "00" * 128)
        callinfo = {
            'calldata': calldata,
            'callvalue': 0,
            'address': contract_address,
            'codesize': len(bytecode),
            'storage_address': contract_address,
            'delegatecall_slot_map': {},
            'caller': "0x" + "cc" * 20,
            'origin': "0x" + "cc" * 20,
        }

        emul = EthereumSSAEngine(bytecode, explorer)
        emul.emulate(callinfo.copy(), state, debug=False, if_storage_analysis=True)

        slot_usage = emul.get_slot_usage()
        current_selector_usage = order_slot_usages(slot_usage, {})

        slot_changes = emul.result.get("slot_value_change", {})

        # Go through slot changes:
        for slot, changes in slot_changes.items():
            slot_entry = slot_profile.get(str(slot), {})

            for change in changes:
                old_value = change["old_value"]
                new_value = change["new_value"]
                change_mask = int(change.get("mask", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 16)

                old_int = int(old_value, 16)
                new_int = int(new_value, 16)

                # Apply mask to old/new value to isolate the variable being written
                masked_old = old_int & change_mask
                masked_new = new_int & change_mask

                # Compute shift amount: how many trailing 0 bits in change_mask?
                shift_amount = (change_mask & -change_mask).bit_length() - 1  # count trailing zeros

                shifted_old = masked_old >> shift_amount
                shifted_new = masked_new >> shift_amount

                for slot_mask_str, slot_info in slot_entry.items():
                    slot_mask = int(slot_mask_str, 16)
                    # Check whether change_mask is a subset of slot_mask
                    if (change_mask & slot_mask) != change_mask:
                        continue  # Skip if write mask exceeds variable mask (possible partial write)

                    # If reaching here, change_mask is covered by slot_mask → valid variable write
                    # Now check for typical initialization patterns:
                    slot_type = slot_info.get("type", "unknown")

                    # For bool: check if masked value is going from 0 → non-zero
                    if slot_type == "bool" and shifted_old == 0 and shifted_new != 0:
                        initialize_slot = slot
                        initialize_mask = slot_mask
                        initialize_flag = True

                    # For address: check if masked new value is non-zero (meaning address is written)
                    elif slot_type == "address" and shifted_new != 0:
                        owner_mask = slot_mask
                        owner_slot = slot
                        owner_flag = True

        # check if there is ISZERO opcode executed of the potential initialize slot during this selector
        if initialize_flag:
            initialize_flag = False
            for slot, subslots in current_selector_usage.items():
                subslots = subslots.get("subslots")
                if int(slot, 16) == initialize_slot:
                    for mask, current_entry in subslots.items():
                        mask = int(mask, 16)
                        if mask == initialize_mask:
                            opcodes = current_entry.get("opcodes", None)
                            ISZERO = opcodes.get("ISZERO", None)
                            if ISZERO:
                                initialize_flag = True
                                # print("[√] find a potential initialize variable")

        # check if the potential sensitive address is used in require(address==caller)
        if initialize_flag and owner_flag:
            owner_flag = False
            for slot, subslots in logic_global_slot_usage.items():
                subslots = subslots.get("subslots")
                if int(slot, 16) == owner_slot:
                    for mask, current_entry in subslots.items():
                        mask = int(mask, 16)
                        if mask == owner_mask:
                            opcodes = current_entry.get("opcodes", None)
                            EQ = opcodes.get("EQ", None)
                            if EQ:
                                for global_entry in EQ:
                                    caller_tag = global_entry.get("tag", "None") if isinstance(global_entry, dict) else "None"
                                    if caller_tag.lower() == "caller":
                                        owner_flag = True

        # === Final result ===
        if initialize_flag and owner_flag:
            # print(f"[!] WARNING: Initialization pattern detected → Contract {contract_address} may suffer from initialization missing issue!")
            # print(f"[!] Initializing selector -> [{selector}]")
            uninitialized_slots_detail_list.append([contract_address,selector])
            found_initialization_pattern = True
            return found_initialization_pattern, uninitialized_slots_detail_list

        # If a slot wasn't initialized, add to uninitialized_slots_detail_list
        # Here you can add logic to record which slots were not initialized (if desired)
        # Example: if we expected slot X to be initialized but initialize_flag == False, record it.

        initialize_flag = False
        owner_flag = False

    # print(f"[+] No initialization missing issue detected.")
    return found_initialization_pattern, uninitialized_slots_detail_list



def check_Missing_permission_control(contract_address, bytecode, owner, owner_slot, owner_mask, delegatecall_slot_map, selectors, explorer):
    print("[+] Trying to check if missing Permission Control")
    code_size = len(bytecode[2:] ) // 2
    permission_check_summary = []  # list of (selector, check_status, details)
    has_permission_missing = False  # New flag

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

        admin_check = emul.result.get('admin_check')
        write_owner = emul.result.get('write_owner')
        owner_writer = emul.result.get('owner_overwriter')
        if_impl_overwrite = emul.result.get("delegate_overwrite")
        overwrite_events = emul.result.get("delegate_overwrite_info")

        # Build summary detail for this selector
        selector_status = "unknown"
        selector_detail = ""

        # Whether this selector does privileged write (owner or logic address)
        privileged_write_detected = write_owner or if_impl_overwrite

        if admin_check is None:
            selector_status = "missing"
            detail_msgs = []
            if write_owner:
                msg = f"owner write detected in logic {owner_writer}"
                detail_msgs.append(msg)
            if if_impl_overwrite:
                for event in overwrite_events:
                    slot = event["slot"]
                    write_address = event["write_address"]
                    new_val = event["new_value"]
                    msg = f"Delegatecall slot {slot} overwritten by {write_address} but no admin check"
                    detail_msgs.append(msg)
            if not detail_msgs:
                detail_msgs.append("no admin check, no privileged operation detected")
            selector_detail = "; ".join(detail_msgs)

            # === Core logic: if privileged_write_detected + no admin_check → permission missing
            if privileged_write_detected:
                has_permission_missing = True  # Set global flag

        else:
            if admin_check == False:
                selector_status = "rejected"
                selector_detail = "Privileged function detected, but rejected."
            else:
                selector_status = "passed"
                detail_msgs = []
                detail_msgs.append("admin check passed")
                if write_owner:
                    msg = f"owner changed by {owner_writer}"
                    detail_msgs.append(msg)
                if if_impl_overwrite:
                    for event in overwrite_events:
                        slot = event["slot"]
                        write_address = event["write_address"]
                        new_val = event["new_value"]
                        msg = f"Delegatecall slot {slot} overwritten by {write_address}"
                        detail_msgs.append(msg)
                if not (write_owner or if_impl_overwrite):
                    detail_msgs.append("no privileged operation detected")
                selector_detail = "; ".join(detail_msgs)

        # Save summary for this selector
        permission_check_summary.append((selector, selector_status, selector_detail))

    # Return summary + whether permission missing was detected
    return has_permission_missing,permission_check_summary