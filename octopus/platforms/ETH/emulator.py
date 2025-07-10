import copy
import time
from logging import getLogger

from eth_hash.auto import keccak
from octopus.core.ssa import SSA, SSA_TYPE_CONSTANT, SSA_TYPE_FUNCTION
from octopus.engine.emulator import EmulatorEngine
from octopus.engine.helper import helper as hlp
from octopus.platforms.ETH.contract import EthereumContract
from octopus.platforms.ETH.disassembler import EthereumDisassembler
from octopus.platforms.ETH.explorer import INFURA_MAINNET, EthereumInfuraExplorer
from octopus.platforms.ETH.ssa import EthereumSSASimplifier
from octopus.platforms.ETH.vmstate import EthereumVMstate
from copy import deepcopy
import re

logging = getLogger(__name__)
INFURA_KEY = "d449de4b0a0c4c2ca8d60fcd0fc544d9"
VALID_FIELD_BYTES = {1, 2, 4, 8,12, 16, 20, 32}
fall_mask = int("0x"+"ff"*20,16)
fall_mask_val = (fall_mask)& ((1 << 256) -1)  


def int_to_address(value: int) -> str:
    """Convert an integer to an Ethereum address."""
    return "0x" + f"{value:0{40}x}"[-40:]

def int_to_slot(value: int) -> str:
    """Convert an integer to a storage slot string with 0x prefix."""
    return "0x" + hex(value)[2:]

def log_slot_usage(self, slot, used_in, with_val=None,with_tag=None):
        if slot not in self.slot_usage_log:
            self.slot_usage_log[slot] = []
        log_entry = {
            "used_in": used_in,
        }
        if with_tag:
            log_entry["with"] = {
                "tag": with_tag,
                "val": with_val
            }
        self.slot_usage_log[slot].append(log_entry)



def is_field_mask(mask):
    return isinstance(mask, int) and mask != 0 and mask.bit_length() % 8 == 0

def is_power_of_two(n):
    return isinstance(n, int) and n != 0 and (n & (n - 1)) == 0

def is_right_shift_by_div(divisor):
    return is_power_of_two(divisor) and (divisor.bit_length() - 1) % 8 == 0


def is_field_mask(mask: int) -> bool:
    if not isinstance(mask, int) or mask == 0:
        return False

    bin_str = bin(mask)[2:].zfill(256)

    # case 1: all 1s
    if '0' not in bin_str:
        return True

    # check for invalid patterns
    if '01' in bin_str and '10' in bin_str:
        return False

    # Check mask pattern: 000...111 or 111...000
    if re.fullmatch(r'0*1*', bin_str) or re.fullmatch(r'1*0*', bin_str):
        # Count number of 1s
        ones = bin_str.count('1')
        field_bytes = ones // 8
        # 如果不是合法字段长度 → 不合法 field mask
        if field_bytes not in VALID_FIELD_BYTES:
            return False
        return True
    else:
        return False


def should_apply_op(op, param_val):
    MAX_SHIFT_BITS = 256
    MIN_SHIFT_BITS = 0
    if op == "DIV" or op == "MUL":
        return is_right_shift_by_div(param_val)
    elif op == "AND":
        return is_field_mask(param_val)
    elif op in ("SHR", "SHL"):
        return (
            isinstance(param_val, int)
            and MIN_SHIFT_BITS <= param_val <= MAX_SHIFT_BITS
            and param_val % 8 == 0
        )
    elif op == "BYTE":
        return isinstance(param_val, int) and (0 <= param_val < 32)
    else:
        return False

def parse_sload_expr_tag(tag):
    pattern = r"SLOAD_SLOT_([0-9a-fA-Fx]+)((?:_[A-Z]+\([^)]*\))*)"
    match = re.match(pattern, tag)
    if not match:
        return None
    base_slot = match.group(1)        # e.g., "0", "0x1f"
    suffix = match.group(2) or ""     # e.g., "_AND(0xff)_DIV(0x100)"
    full_key = f"{base_slot}{suffix}" # e.g., "0_AND(0xff)_DIV(0x100)"
    return {
        "slot": base_slot,
        "expr_key": full_key  # <--- use this as dict key
    }

def process_operation_tags(self, tags, vals, op):
    sload_tag = None
    env_tag = None

    # Ensure the length is consistent (if not, pad vals with None)
    if len(vals) < len(tags):
        vals += [None] * (len(tags) - len(vals))

    updated_tags = tags.copy()

    # === Step 1: Binary op top-2 handling ===
    if op in {"DIV", "MUL", "AND", "SHR", "SHL", "BYTE"} and len(tags) >= 2:
        tag1, tag2 = updated_tags[-2], updated_tags[-1]
        val1, val2 = vals[-2], vals[-1]

        # Case 1: left is SLOAD_SLOT_
        if tag1.startswith("SLOAD_SLOT_") and should_apply_op(op, val2):
            tag1 += f"_{op}({hex(val2)})" if op != "BYTE" else f"_{op}({val2})"
            updated_tags[-2] = tag1
            updated_tags[-1] = tag1
            return tag1

        # Case 2: right is SLOAD_SLOT_
        elif tag2.startswith("SLOAD_SLOT_") and should_apply_op(op, val1):
            tag2 += f"_{op}({hex(val1)})" if op != "BYTE" else f"_{op}({val1})"
            updated_tags[-2] = tag2
            updated_tags[-1] = tag2
            return tag2

    # === Step 2: Log usage ===
    for idx, (tag, val) in enumerate(zip(updated_tags, vals)):
        if tag.startswith("SLOAD_SLOT_"):
            expr_info = parse_sload_expr_tag(tag)

            slot_id = expr_info["expr_key"]

            other_tags = [t for i, t in enumerate(updated_tags) if i != idx]
            val_for_with = next(
                (hex(v) if isinstance(v, int) else str(v)
                 for i, v in enumerate(vals) if i != idx and v is not None),
                None
            )
            with_tag = ",".join(other_tags) if other_tags else None

            log_slot_usage(
                self,
                slot=slot_id,
                used_in=op,
                with_val=val_for_with,
                with_tag=with_tag,
            )

            sload_tag = tag

        # Check for environment-related tags (caller, origin, etc.)
        elif any(tag.startswith(prefix) for prefix in [
            "CALLER", "ORIGIN", "CALLVALUE", "CALLDATALOAD", "CALLDATASIZE", "CALLDATACOPY",
            "CODESIZE", "CODECOPY", "GAS", "GASPRICE", "COINBASE", "TIMESTAMP", "NUMBER",
            "DIFFICULTY", "CHAINID", "BASEFEE", "BALANCE", "SELFBALANCE", "PC", "MSIZE",
        ]):
            if env_tag is None:
                env_tag = tag

    # === Step 3: Boolean operations ===
    if op in ["LT", "GT", "SLT", "SGT", "EQ", "ISZERO"]:
        return  "bool"
    # === Step 5: Return preferred tag ===
    sha3_tag = next((t for t in updated_tags if t.startswith("SHA3(")), None)
    if sha3_tag:
        return sha3_tag
    elif env_tag:
        return env_tag
    elif sload_tag:
        return  sload_tag
    else:
        return f"{op}(" + ",".join(tags) + ")"





class EthereumEmulatorEngine(EmulatorEngine):

    def __init__(self, bytecode, explorer):
        self.if_storage_analysis = False
        self.trace = []
        self.tag_stack = []  # shadow stack for symbolic tracking
        self.tag_memory = {}  # shadow memory for symbolic tracking
        self.tag_storage = {} # shadow storage for symbolic tracking

        self.slot_usage_log = {}  # track storage slot usage

        self.recent_ssotre_related_mask = "0x"+"ff"*32 # track for the recent sstore related AND 

        self.bytecode = bytecode

        # retrive instructions, basicblocks & functions statically
        disasm = EthereumDisassembler(bytecode)
        # pass runtime code no need to analysis
        self.instructions = disasm.disassemble(analysis=False)
        self.reverse_instructions = {k: v for k, v in enumerate(self.instructions)}

        self.states = dict()
        self.states_total = 0


        self.current_slot = None  # save current visited slot
        self.current_sload_value = None # save current sload value
        self.current_store_value = None # save current store value
        self.current_compare_x = None # save current compare x
        self.current_compare_y = None # save current compare y


        self.bytecode = disasm.bytecode  # get the run time bytecode from disasm
        self.result = {}
        self.handler = Handler(explorer)  # handle info outside contract
        self.delegate_info = []  # record delegate call info
        self.meet_inconcrete_opcode = set() # check if meet inconcrete opcode like block number or basefee

    def emulate(self, callinfo, state=None, debug = False,if_storage_analysis=False):
        self.if_storage_analysis = if_storage_analysis
        self.result["write_owner"] = False
        state = state or EthereumVMstate(self.handler.explorer)
        self.meet_inconcrete_opcode = set()
        # self.result = {}
        self.delegate_info = []  # record delegate call info
        # handle call return data
        self.has_call = False
        self.return_buffer = b''

        # callinfo check
        try:
            for i in ['address','caller','origin','codesize','storage_address']:
                if(callinfo.get(i) == None):
                    raise Exception("callinfo error: need "+i)
        except Exception as e:
            print(e)
            return
        #pre process calldata
        #convert calldata to bytes
        if(callinfo.get('calldata') != None):
            if type(callinfo['calldata']) == str:
                if(callinfo['calldata'][:2] == '0x'):
                    callinfo['calldata'] = callinfo['calldata'][2:]
                callinfo['calldata'] = bytes.fromhex(callinfo['calldata'])
        else:
            callinfo['calldata'] = b''

        if(callinfo.get('gas') != None):
            state.gas = callinfo.get('gas')

        # get current instruction
        instr = self.reverse_instructions[state.pc]

        # halt variable use to catch ending branch
        halt = False
        while not halt:

            # get current instruction
            instr = self.reverse_instructions[state.pc]
            # print(f"[DEBUG][PC={state.pc}] opcode={instr.name}")


            # Save instruction and state
            state.instr = instr
            self.states[self.states_total] = state
            self.states_total += 1
            state.pc += 1

            # execute single instruction
            halt = self.emulate_one_instruction(callinfo, instr, state, debug)

    def get_result(self):
        return self.result

    def get_delegate_info(self):
        return self.delegate_info
    
    def get_slot_usage(self):
        return self.slot_usage_log
 
    #return bool
    def contains_inconcrete_opcode(self):
        return len(self.meet_inconcrete_opcode) > 0

    def emulate_one_instruction(self, callinfo, instr, state, debug):
        if(debug):
            if instr.operand_interpretation:
                print ('\033[1;32m Instr \033[0m',hex(state.pc-1), instr.name, hex(instr.operand_interpretation))
            else:
                print ('\033[1;32m Instr \033[0m', hex(state.pc-1), instr.name)
        state.gas -= instr.fee
        halt = False

        #
        #  0s: Stop and Arithmetic Operations
        #
        if instr.name == 'STOP':
            halt = True

        elif instr.is_arithmetic:
            self.emul_arithmetic_instruction(instr, state)
        #
        #  10s: Comparison & Bitwise Logic Operations
        #
        elif instr.is_comparaison_logic:
            self.emul_comparaison_logic_instruction(callinfo,instr,state)
        #
        #  20s: SHA3
        #
        elif instr.is_sha3:
            self.emul_sha3_instruction(instr, state)
        #                                                               
        #  30s: Environment Information
        #
        elif instr.is_environmental:
            self.ssa_environmental_instruction(callinfo, instr, state)
            if instr.name in ("ORIGIN","GASPRICE","BALANCE"):
                self.meet_inconcrete_opcode.add(instr.name)

        #
        #  40s: Block Information
        #
        elif instr.uses_block_info:
            self.ssa_block_instruction(callinfo, instr, state)
            self.meet_inconcrete_opcode.add(instr.name)
            #halt = True
        #
        #  50s: Stack, Memory, Storage, and Flow Information
        #
        elif instr.uses_stack_block_storage_info:
            halt = self.ssa_stack_memory_storage_flow_instruction(callinfo, instr, state)
        #
        #  60s & 70s: Push Operations
        #
        elif instr.name.startswith("PUSH"):
            state._stack.append(instr.operand_interpretation)

            push_bytes = int(instr.name[4:])
            push_bits = push_bytes * 8

            if push_bits == 160:  # 20 字节，可能是地址
                tag = "address"
            else:
                tag = instr.name
            self.tag_stack.append(tag)
        #
        #  80s: Duplication Operations
        #
        elif instr.name.startswith('DUP'):
            # DUPn (eg. DUP1: a b c -> a b c c, DUP3: a b c -> a b c a)
            position = instr.pops  # == XX from DUPXX
            state._stack.append(state._stack[- position])
            self.tag_stack.append(self.tag_stack[-position])
        #
        #  90s: Swap Operations
        #
        elif instr.name.startswith('SWAP'):
            # SWAPn (eg. SWAP1: a b c d -> a b d c, SWAP3: a b c d -> d b c a)
            position = instr.pops - 1  # == XX from SWAPXX
            temp = state._stack[-position - 1]
            state._stack[-position - 1] = state._stack[-1]
            state._stack[-1] = temp
            
            temp_tag = self.tag_stack[-position - 1]
            self.tag_stack[-position - 1] = self.tag_stack[-1]
            self.tag_stack[-1] = temp_tag
        #
        #  a0s: Logging Operations
        #
        elif instr.name.startswith('LOG'):
            # only stack operations emulated
            arg = [state._stack.pop() for x in range(instr.pops)]
            _ = [self.tag_stack.pop() for x in range(instr.pops)]
        #
        #  f0s: System Operations
        #
        elif instr.is_system:
            halt = self.ssa_system_instruction(callinfo, instr, state, debug)
            if instr.name in ("CREATE","CREATE2"):
                self.meet_inconcrete_opcode.add(instr.name)

        # UNKNOWN INSTRUCTION
        else:
            logging.warning('UNKNOWN = ' + instr.name)
            halt = True
        if(debug == True):
            print ('stack: ',list(map(lambda x: x if(type(x)==str) else hex(x),state._stack)))
            print ('storage: ', list(map(lambda x: (hex(x),hex(state.storage[x])),state.storage)))
            print ('memory: ', state.memory)
        # save last opcode to result
        self.result['opcode'] = str(instr.name)
        if self.if_storage_analysis:
            print(f"[opcode={instr.name}]")
            print(f"state._stack = {list(map(lambda x: x if(type(x)==str) else hex(x),state._stack))}")
            print(f"tag_stack = {list(self.tag_stack)}")
            instr_trace = {
                "pc": state.pc - 1,
                "op": instr.name,
                "stack": list(state._stack),
                "tags": list(self.tag_stack),
            }
            self.trace.append(instr_trace)

        return halt

    def emul_arithmetic_instruction(self, instr, state):
        op = instr.name
        x=None
        y=None
        m=None

        if op == 'ADD':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(x + y)))
        elif op == 'SUB':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(x - y)))
        elif op == 'MUL':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(x * y)))
        elif op == 'DIV':
            x = state._stack.pop()
            y = state._stack.pop()
            if y == 0:
                state._stack.append(0)
            else:
                state._stack.append(hlp.get_concrete_int(x//y))
        elif op == 'MOD':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(0 if y == 0 else x % y))
        elif op == 'SDIV':
            x = hlp.to_signed(state._stack.pop())
            y = hlp.to_signed(state._stack.pop())
            sign = 1 if(x*y) >= 0 else -1
            computed = sign*(abs(x)//abs(y)) if(y!=0) else 0
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(computed)))
        elif op == 'SMOD':
            x = hlp.to_signed(state._stack.pop())
            y = hlp.to_signed(state._stack.pop())
            sign = -1 if x < 0 else 1
            computed = sign * (abs(x) % abs(y))
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(computed)))
        elif op == 'EXP':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(pow(x, y))))
        elif op == 'SIGNEXTEND':
            x = state._stack.pop()
            y = state._stack.pop()
            mask = 2**(8*(x+1))
            sign_max_plus_one = mask >> 1
            y &= mask - 1
            y = y if(y < sign_max_plus_one) else y - mask
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(y)))
        elif op == 'ADDMOD':
            x = state._stack.pop()
            y = state._stack.pop()
            m = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec((x+y)%m)))
        elif op == 'MULMOD':
            x = state._stack.pop()
            y = state._stack.pop()
            m = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec((x*y)%m)))

        # track the tag for symbolic analysis
        if op in ['ADDMOD', 'MULMOD']:
            # For ADDMOD and MULMOD, we need to pop the tags as well
            tag0 = self.tag_stack.pop()
            tag1 = self.tag_stack.pop()
            tag2 = self.tag_stack.pop()


            tag = process_operation_tags(self, [tag0, tag1, tag2],[x,y,m], op)
            self.tag_stack.append(tag)  # track the tag for symbolic analysis
        else:
            tag0 = self.tag_stack.pop()
            tag1 = self.tag_stack.pop()

            tag = process_operation_tags(self, [tag0, tag1], [x,y],op)
            self.tag_stack.append(tag)

    def emul_comparaison_logic_instruction(self, callinfo,instr, state):
        op = instr.name
        x = None
        y = None

        if op == 'LT':
            x = state._stack.pop()
            y = state._stack.pop()
            if x < y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'GT':
            x = state._stack.pop()
            y = state._stack.pop()
            if x > y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'SLT':
            x = state._stack.pop()
            y = state._stack.pop()
            x = hlp.to_signed(x)
            y = hlp.to_signed(y)
            if x < y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'SGT':
            x = state._stack.pop()
            y = state._stack.pop()
            x = hlp.to_signed(x)
            y = hlp.to_signed(y)
            if x > y:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'EQ':
            x = state._stack.pop()
            y = state._stack.pop()
            self.current_compare_x = x
            self.current_compare_y = y
            if x == y:
                state._stack.append(1)
            else:
                state._stack.append(0)
            # print(f"[DEBUG][EQ] comparing {hex(x)} == {hex(y)}")

            # identify msg.sender == SLOAD(...) mode
            if callinfo.get("if_delegatecall")==True:
                caller = callinfo['origin']
                # print(f"[DEBUG] In DELEGATECALL, CALLER = {caller}")
            else:
                caller = callinfo['caller']
            caller_val = int(caller, 16)  # 统一转成整数

            if x == caller_val or y == caller_val:
                # print(f"[DEBUG] In DELEGATECALL, CALLER = {caller}")
                # print(f"x = {x}, y = {y}, caller_val = {caller_val}")
                if x == y:
                    self.result["admin_check"] = True
                else:
                    self.result["admin_check"] = False
                if x == caller_val:
                    self.result["owner"] = y
                    # print(f"[+] owner: {y}")
                else:
                    self.result["owner"] = x

        elif op == 'AND':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(x&y)
        elif op == 'OR':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(x|y)
        elif op == 'XOR':
            x = state._stack.pop()
            y = state._stack.pop()
            state._stack.append(x^y)
        elif op == 'BYTE':
            n = state._stack.pop()
            x = state._stack.pop()
            state._stack.append(int((x).to_bytes(32, byteorder="big")[n]))
        elif op == 'ISZERO':
            x = state._stack.pop()
            if x == 0:
                state._stack.append(1)
            else:
                state._stack.append(0)
        elif op == 'NOT':
            x = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(~x)))
        elif op == 'SHL':
            shift = state._stack.pop()
            x = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(x << shift)))
        elif op == 'SHR':
            shift = state._stack.pop()
            x = state._stack.pop()
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(x >> shift)))
        elif op == 'SAR':
            shift = state._stack.pop()
            x = state._stack.pop()
            x = hlp.to_signed(x)
            state._stack.append(hlp.get_concrete_int(hlp.convert_to_bitvec(x >> shift)))
        
        if op in ['LT', 'GT', 'SLT', 'SGT','EQ','AND', 'OR', 'XOR', 'SHL', 'SHR', 'SAR','BYTE']:
            tag2 = self.tag_stack.pop()
            tag1 = self.tag_stack.pop()

            tag = process_operation_tags(self, [tag1, tag2],[y,x], op)
            self.tag_stack.append(tag)  # track the tag for symbolic analysis

            if op == 'AND':
                inverted = None
                if tag1.startswith("SLOAD_SLOT_"):
                    inverted = (~x) & ((1 << 256) -1)  
                    self.recent_ssotre_related_mask = hex(inverted)
                elif tag2.startswith("SLOAD_SLOT_"):
                    inverted = (~y) & ((1 << 256) -1)  
                    self.recent_ssotre_related_mask = hex(inverted)
                else:
                    pass
        else:
            tag1 = self.tag_stack.pop()

            tag = process_operation_tags(self, [tag1], [x],op)
            self.tag_stack.append(tag)  # track the tag for symbolic analysis 

        
        


    def emul_sha3_instruction(self, instr, state):
        pos = state._stack.pop()
        n = state._stack.pop()
        self.tag_stack.pop() 
        self.tag_stack.pop()  
        mem_val = state.memory[pos:pos+n]
        sha3 = int(keccak(state.memory[pos:pos+n]).hex(),16)
        taints = None
        tag = None
        if n == 32:
            i = pos+1
            mem_tag = self.tag_memory.get(i)
            taints = mem_tag
            slot = mem_val[-1]
            base_tag = taints if taints and ("Array" in taints or "Mapping" in taints) else slot
            tag = f"SHA3(Array, Base_slot={base_tag})"

        elif n == 64:
            i = pos+33
            mem_tag = self.tag_memory.get(i)
            taints = mem_tag
            mapping_slot_bytes = bytes(state.memory[pos+32:pos+64])
            mapping_selector_bytes = bytes(state.memory[pos:pos+32])
            mapping_base_slot_int = int.from_bytes(mapping_slot_bytes, byteorder='big')
            mapping_selector_int = int.from_bytes(mapping_selector_bytes, byteorder='big')
            mapping_selector = int_to_slot(mapping_selector_int)

            base_tag = taints if taints and ("Array" in taints or "Mapping" in taints) else mapping_base_slot_int
            tag = f"SHA3(Mapping,selector={mapping_selector},Mapping_slot={base_tag})"

        else:
            tag = f"SHA3({taints})"


        self.tag_stack.append(tag)  # track the tag for symbolic analysis
        state._stack.append(sha3)


    def ssa_environmental_instruction(self, callinfo, instr, state):
        if instr.name in ['ADDRESS', 'ORIGIN', 'CALLER', 'CALLVALUE', 'CALLDATASIZE', 'CODESIZE', 'RETURNDATASIZE', 'GASPRICE']:
            self.tag_stack.append(instr.name)  # track the tag for symbolic analysis
            op = instr.name
            if op == 'CALLDATASIZE':
                v = len(callinfo["calldata"]) if(callinfo['calldata']) else 0
                state._stack.append(v)
            elif op == 'CALLVALUE':
                v = callinfo.get('callvalue', 0)
                state._stack.append(v)
            elif op == 'ADDRESS':
                if callinfo.get("if_delegatecall")==True:
                    v = callinfo.get('storage_address')
                    # print(f"[DEBUG] In DELEGATECALL, ADDRESS = {v}")
                else:
                    v = callinfo.get('address')
                    # print(f"[DEBUG] In DIRECT CALL, ADDRESS = {v}")
                # = "ADDRESS" if(v == None) else v
                state._stack.append(int(v,16))
            elif op == 'RETURNDATASIZE':
                if(self.has_call):
                    state._stack.append(len(self.return_buffer))
                else:
                    state._stack.append(0)
            elif op == "CODESIZE":
                state._stack.append(callinfo['codesize'])
            elif op == "CALLER":
                if callinfo.get("if_delegatecall")==True:
                    caller = callinfo.get('origin')
                    # print(f"[DEBUG] In DELEGATECALL, CALLER = {caller}")
                else:
                    caller = callinfo['caller']
                caller = int(caller, 16)
                state._stack.append(caller)
            elif op == "ORIGIN":
                origin = callinfo['origin']
                origin = int(origin, 16)
                state._stack.append(origin)
            elif op == "GASPRICE":
                state._stack.append(self.handler.get_gas_price())

        elif instr.name in ['BALANCE', 'CALLDATALOAD', 'EXTCODESIZE', 'EXTCODEHASH']:
            if instr.name == 'CALLDATALOAD':
                pos = state._stack.pop()
                pos_end = pos + 0x20
                tmp = callinfo['calldata'][pos:pos_end]
                if(len(tmp) < 0x20):
                    tmp += bytes(0x20 - len(tmp))
                v = int(tmp.hex(),16)
                state._stack.append(v)
            elif instr.name == 'EXTCODESIZE':
                ext_addr = int_to_address(state._stack.pop())
                ret = self.handler.get_extCodeSize(ext_addr)
                state._stack.append(ret)
            elif instr.name == 'EXTCODEHASH':
                ext_addr = int_to_address(state._stack.pop())
                ret = self.handler.get_extCodeHash(ext_addr)
                state._stack.append(ret)
            elif instr.name == 'BALANCE':
                ext_addr = int_to_address(state._stack.pop())
                bal = self.handler.get_balance(ext_addr)
                state._stack.append(bal)
            self.tag_stack.pop()  # pop the tag for symbolic analysis
            self.tag_stack.append(instr.name)  # track the tag for symbolic analysis

        elif instr.name in ['CALLDATACOPY', 'CODECOPY', 'RETURNDATACOPY']:
            dst_offset = state._stack.pop()
            offset = state._stack.pop()
            length = state._stack.pop()
            _=self.tag_stack.pop() 
            _=self.tag_stack.pop() 
            _=self.tag_stack.pop() 
            if(len(state.memory) < dst_offset + length):
                state.memory.mextend( dst_offset + length)
            if( instr.name == 'CALLDATACOPY'):
                if(length > 0):
                    v = callinfo["calldata"][offset:offset+length]
                    state.memory[dst_offset:dst_offset+length] = v
                    tag = "CALLDATA"
            elif( instr.name == 'CODECOPY'):
                v = self.bytecode[ offset : offset+length]
                state.memory[ dst_offset : dst_offset+length] = v
                tag = "BYTECODE"
            elif( instr.name == 'RETURNDATACOPY'):
                state.memory[dst_offset:dst_offset+length] = self.return_buffer[offset:offset+length]
                tag = "RETURNDATA"
            
            for i in range(dst_offset, dst_offset + length):
                self.tag_memory[i] = tag
            


        elif instr.name == 'EXTCODECOPY':
            addr = int_to_address(state._stack.pop())
            dst_offset = state._stack.pop()
            offset = state._stack.pop()
            length = state._stack.pop()
            _ = self.tag_stack.pop() 
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()
            ext_code = self.handler.get_extCode(addr)
            state.memory[dst_offset:dst_offset+length] = ext_code[offset:offset+length]
            for i in range(dst_offset, dst_offset + length):
                self.tag_memory[i] = tag

    def ssa_block_instruction(self, callinfo, instr, state):

        if instr.name == 'BLOCKHASH':
            blocknumber = state._stack.pop()
            self.tag_stack.pop() # track the tag for symbolic analysis
            b = self.handler.get_block_by_number(blocknumber)
            state._stack.append(int(b['hash'],16))
        elif instr.name == 'DIFFICULTY':
            state._stack.append(self.handler.get_difficulty())
        elif instr.name == 'CHAINID':
            state._stack.append(1)
        elif instr.name == 'GASLIMIT':
            state._stack.append(self.handler.get_gas_limit())
        elif instr.name == 'BASEFEE':
            state._stack.append(50*10**9) #50 Gwei
        elif instr.name == 'TIMESTAMP':
            state._stack.append(int(time.time()))
        elif instr.name == 'COINBASE':
            state._stack.append(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
        elif instr.name == 'NUMBER':
            state._stack.append(self.handler.get_block_number())
        elif instr.name == 'SELFBALANCE':
            state._stack.append(self.handler.get_balance(callinfo['address']))
        self.tag_stack.append(instr.name)  # track the tag for symbolic analysis

    def ssa_stack_memory_storage_flow_instruction(self, callinfo, instr, state):

        halt = False
        op = instr.name

        if op == 'POP':
            state._stack.pop()
            self.tag_stack.pop()  # pop the tag for symbolic analysis

        elif op in ['MLOAD', 'SLOAD']:
            if op == 'MLOAD':
                mem_pos = state._stack.pop()
                self.tag_stack.pop()  # pop the tag for symbolic analysis
                #mem_end = mem_pos + 0x20
                #mem_val = int(state.memory[mem_pos:mem_end].hex(),16)
                mem_val = state.memory.mload(mem_pos)
                state._stack.append(mem_val)
                taints = set()
                for i in range(mem_pos, mem_pos + 32):
                    tag = self.tag_memory.get(i)
                    if tag:
                        taints.add(tag)
                tag = process_operation_tags(self, list(taints), [mem_val],op)
                self.tag_stack.append(tag)

            if op == 'SLOAD':
                storage_pos = state._stack.pop()
                storage_val = state.storage.sload(callinfo.get('storage_address'), storage_pos)
                state._stack.append(storage_val)
                source_tag = self.tag_stack.pop()
                self.tag_stack.append(f"SLOAD_SLOT_{storage_pos}")  # eg. "SLOAD_SLOT_0x0"

                self.current_slot = storage_pos
                self.current_sload_value = storage_val

                if storage_pos not in  self.slot_usage_log:
                    self.slot_usage_log[storage_pos] = []
                log_entry = {
                    "source":{ 
                        "tag":source_tag
                    }
                }
                self.slot_usage_log[storage_pos].append(log_entry)

                # recoganize delegatecall address
                delegate_targets = callinfo.get("delegatecall_addr")
                if isinstance(storage_val, int):
                    val_as_address = int_to_address(storage_val).lower()
                    if delegate_targets != None:
                        for addr in delegate_targets:
                            if val_as_address == addr:
                                if callinfo["address"] != callinfo["origin_proxy"]:
                                    self.result["beacon_addr"] = callinfo["address"]
                                    # print(f"[DEBUG] beacon_addr: {callinfo['address']}")
                                # print(f"[debug] sload val_as_address: {val_as_address} is delegatecall addr")
                                self.result.setdefault("delegatecall_slot_map", {})[
                                    val_as_address
                                ] = (callinfo["storage_address"], storage_pos)



        elif op in ['MSTORE', 'MSTORE8', 'SSTORE']:
            if op == 'MSTORE':
                pos = state._stack.pop()
                val = state._stack.pop()
                tag_pos = self.tag_stack.pop()
                tag_val = self.tag_stack.pop()

                state.memory.mstore(pos,val)
                for i in range(pos, pos + 32):
                    self.tag_memory[i] = tag_val
                # print(f"tag_memory:{self.tag_memory}")
            elif op == 'MSTORE8':
                pos = state._stack.pop()
                val = state._stack.pop()
                tag_pos = self.tag_stack.pop()
                tag_val = self.tag_stack.pop()

                state.memory.mstore8(pos,val)
                self.tag_memory[tag_pos] = tag_val
            elif op == 'SSTORE':
                pos = state._stack.pop()
                val = state._stack.pop()

                tag_source = self.tag_stack.pop()
                val_from = self.tag_stack.pop()

                # === Step 1: record slot change ===
                # Initialize slot_value_change dict if not present
                self.result.setdefault("slot_value_change", {})

                # Read current stored value (old_value)
                old_val = state.storage.sload(callinfo.get('storage_address'),pos)

                # Save old → new value pair
                self.result["slot_value_change"].setdefault(pos, []).append({
                    "old_value": hex(old_val) if old_val is not None else "None",
                    "new_value": hex(val),
                    "mask":self.recent_ssotre_related_mask
                })

                # === Step 2: normal sstore logging ===
                state.storage.sstore(pos, val)

                if pos not in self.slot_usage_log:
                    self.slot_usage_log[pos] = []
                log_entry = {
                    "write_from": {
                        "tag": val_from,
                        "val": hex(val)
                    }
                }
                log_entry["source"] = {
                    "tag": tag_source
                }
                self.slot_usage_log[pos].append(log_entry)

                self.current_store_value = val
  
                # === Step 3: owner slot tracking ===
                mask_val = int(self.recent_ssotre_related_mask,16)
                owner_slot = callinfo.get("owner_slot")
                owner_mask = callinfo.get("owner_mask")
                owner_mask_val = 0
                if owner_mask:
                    owner_mask_val = int(owner_mask,16)
                owner_mask_val_int = int(owner_mask_val, 16) if isinstance(owner_mask_val, str) else owner_mask_val
                write_to_mask_val_int = int(mask_val, 16) if isinstance(mask_val, str) else mask_val
                fall_mask_val_int = int(fall_mask_val, 16) if isinstance(fall_mask_val, str) else fall_mask_val
                pos = int(pos, 16) if isinstance(pos, str) else pos
                owner_slot = int(owner_slot, 16) if isinstance(owner_slot, str) else owner_slot
                
                if pos == owner_slot and (write_to_mask_val_int == owner_mask_val_int or write_to_mask_val_int == fall_mask_val_int):
                    self.result["write_owner"] = True
                    self.result["owner_overwriter"] = callinfo.get("address")

                # === Step 4: delegate slot tracking ===
                delegate_slot_map = callinfo["delegatecall_slot_map"]
                if delegate_slot_map is not None:
                    for logic_addr, (storage_address, slot) in delegate_slot_map.items():
                        if slot == pos:
                            new_impl_addr = int_to_address(val).lower()
                            self.result["delegate_overwrite"] = True
                            self.result.setdefault("delegate_overwrite_info", []).append({
                                "write_address": callinfo["address"],
                                "slot": pos,
                                "new_value": new_impl_addr
                            })




        elif op == 'JUMP':
            jump_addr = state._stack.pop()
            self.tag_stack.pop()  # pop the tag for JUMP
            target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
            if target.name != "JUMPDEST":
                logging.info('[X] Bad JUMP to 0x%x' % jump_addr)
                halt = True
            state.pc = self.instructions.index(target)

        elif op == 'JUMPI':
            jump_addr = state._stack.pop()
            self.tag_stack.pop()  # pop the tag for JUMPI
            con = state._stack.pop()
            self.tag_stack.pop()  # pop the tag for JUMPI condition
            target = next(filter(lambda element: element.offset == jump_addr, self.instructions))
            if target.name != "JUMPDEST":
                logging.info('[X] Bad JUMP to 0x%x' % jump_addr)
                halt = True
            if con:
                state.pc = self.instructions.index(target)

        elif op in ['PC', 'MSIZE', 'GAS']:
            self.tag_stack.append(op)  # track the tag for symbolic analysis
            if(op == 'PC'):
                state._stack.append(state.pc-1)
            elif(op == 'GAS'):
                state._stack.append(state.gas)
            elif(op == 'MSIZE'):
                state._stack.append(len(state.memory))

        elif op == 'JUMPDEST':
            pass

        return halt

    def ssa_system_instruction(self, callinfo, instr, state, debug=False):

        halt = False

        if instr.name == 'CREATE':
            value = state._stack.pop()
            offset = state._stack.pop()
            length = state._stack.pop()
            _ = self.tag_stack.pop()  
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()
            (create_success, create_address) = self.handler.create( callinfo.copy(), state.memory[offset:offset+length], debug)
            state._stack.append(create_address)
            self.tag_stack.append("address")
            if not create_success:
                halt = True
            #halt = True

        elif instr.name in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
            self.has_call = True
            tag = None
            if instr.name in ('CALL', 'CALLCODE'):
                gas = state._stack.pop()
                _ = self.tag_stack.pop()
                addr = int_to_address(state._stack.pop())
                tag = self.tag_stack.pop()
                value = state._stack.pop()
                arg_offset = state._stack.pop()
                arg_length = state._stack.pop()
                ret_offset = state._stack.pop()
                ret_length = state._stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()
                pass_callinfo = callinfo.copy()
                pass_callinfo['calldata'] = state.memory[arg_offset:arg_offset+arg_length]
                pass_callinfo['address'] = addr
                if(instr.name == 'CALL'):
                    pass_callinfo['storage_address'] = addr
                pass_callinfo['gas'] = gas
                pass_callinfo['value'] = value
                pass_callinfo['caller'] = callinfo['address']
                (call_result, call_slo_usage_log,delegate_info) = self.handler.call(pass_callinfo.copy(), debug)
                beacon_addr = call_result.get("beacon_addr")
                if beacon_addr != None:
                    self.result["beacon_addr"] = beacon_addr
                if(call_result.get('opcode','ERROR') in ['RETURN, REVERT']):
                    state._stack.append(call_result['success'])
                    self.tag_stack.append("call_result")
                    self.return_buffer = call_result['return_data']
                    state.memory[ret_offset:ret_offset+ret_length] = self.return_buffer[:ret_length]
                    for i in range(ret_offset, ret_offset + ret_length):
                        self.tag_memory[i] = "return_data"
                else:
                    self.result['callinfo'] = pass_callinfo
                    self.result['call_result'] = call_result
                    
                    halt = True

            else:
                gas = state._stack.pop()
                _ = self.tag_stack.pop()
                init_addr = state._stack.pop()
                tag = self.tag_stack.pop()

                addr = int_to_address(init_addr)

                arg_offset = state._stack.pop()
                arg_length = state._stack.pop()
                ret_offset = state._stack.pop()
                ret_length = state._stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()
                _ = self.tag_stack.pop()

                #halt = True
                #save the result
                pass_callinfo = callinfo.copy()
                pass_callinfo['calldata'] = state.memory[arg_offset:arg_offset+arg_length]
                pass_callinfo['gas'] = gas
                if instr.name == 'DELEGATECALL':
                    pass_callinfo['if_delegatecall'] = True
                    pass_callinfo['address'] = addr
                    pass_callinfo['storage_address'] = callinfo['address']
                else:
                    pass_callinfo['if_delegatecall'] = False
                    pass_callinfo['address'] = addr
                    pass_callinfo['storage_address'] = addr
                (call_result, call_slo_usage_log,delegate_info) = self.handler.call(pass_callinfo.copy(), debug)
                # print(f"[DEBUG] call_result: {call_result}")
                self.merge_call_result_into_self(call_result)
                self.merge_slot_usage_into_self(call_slo_usage_log)
                if(call_result.get('opcode','ERROR') in ['RETURN', 'REVERT']):
                    state._stack.append(call_result['success'])
                    self.tag_stack.append("call_result")
                    self.return_buffer = call_result['return_data']
                    state.memory[ret_offset:ret_offset+ret_length] = self.return_buffer[:ret_length]
                    for i in range(ret_offset, ret_offset + ret_length):
                        self.tag_memory[i] = "return_data"
                else:
                    self.result['callinfo'] = pass_callinfo
                    self.result['call_result'] = call_result
                    halt = True
                if(instr.name == 'DELEGATECALL'):
                    self.result["owner_slot"] = call_result.get("owner_slot")
                    self.result["owner"] = call_result.get("owner")
                    self.result["write_owner"] = call_result.get("write_owner")
                    self.result["admin_check"] = call_result.get("admin_check")
                    self.result["likely_logic_slot"] = self.current_slot

                    tmp = pass_callinfo.copy()
                    tmp["delegate_target"] = addr
                    tmp["likely_logic_slot"] = self.current_slot
                    tmp['being_called_addr'] = callinfo['address']
                    tmp["arg_offset"] = arg_offset
                    tmp["arg_length"] = arg_length
                    tmp["call_result"] = call_result
                    tmp["delegate_info"] = delegate_info
                    self.delegate_info.append(tmp)

                #record if val is used to call
                # print(f"now in ssa_system_instruction, instr.name = {instr.name}, tag = {tag}")
                if tag.startswith("SLOAD_SLOT_"):
                    # print("[DEBUG] SLOAD_SLOT detected in CALL/DELEGATECALL")
                    slot_id = tag[11:]
                    if slot_id not in self.slot_usage_log:
                        self.slot_usage_log[slot_id] = []
                    log_entry = {
                        "used_in": instr.name,
                    }
                    self.slot_usage_log[slot_id].append(log_entry)

        elif instr.name == 'CREATE2':
            value = state._stack.pop()
            offset = state._stack.pop()
            length = state._stack.pop()
            salt = state._stack.pop()
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()

            (create_success, create_address) = self.handler.create( callinfo.copy(), state.memory[offset:offset+length], debug)
            state._stack.append(create_address)
            self.tag_stack.append("address")
            if not create_success:
                halt = True
            #halt = True

        elif instr.name in ['RETURN', 'REVERT']:
            offset = state._stack.pop()
            length = state._stack.pop()
            _ = self.tag_stack.pop()
            _ = self.tag_stack.pop()

            self.result["opcode"] = str(instr.name)
            self.result["return_data"] = state.memory[offset:offset+length]
            self.result["success"] = 1 if(instr.name == 'RETURN') else 0
            halt = True

        elif instr.name in ['INVALID', 'SELFDESTRUCT']:
            halt = True

        return halt


class EthereumSSAEngine(EthereumEmulatorEngine):

    def __init__(self, bytecode=None, explorer=None):
        EthereumEmulatorEngine.__init__(self, bytecode, explorer)

    def merge_call_result_into_self(self, call_result: dict):
        """
        Merge non-None values from call_result into self.result.

        Args:
            call_result (dict): The result dictionary returned from a sub-call.
        """
        if not isinstance(call_result, dict):
            return
        
        for key, value in call_result.items():
            if value is not None:
                self.result[key] = value
    
    def get_trace(self):
        return self.trace
    
    def get_slot_usage(self):
        """
        Get the slot usage information from the result.
        """
        return self.slot_usage_log
    
    def merge_slot_usage_into_self(self, sub_slot_usage_log):
        """
        Merge slot_usage_log from sub-call into self.slot_usage_log.
        This version is for flat list-based slot_usage_log (not structured).
        """
        if not isinstance(sub_slot_usage_log, dict):
            print(f"[WARN] merge_slot_usage_into_self: sub_slot_usage_log not dict → {type(sub_slot_usage_log)} → skip")
            return

        for slot, data_list in sub_slot_usage_log.items():
            if not isinstance(data_list, list):
                print(f"[WARN] Slot {slot} data not list → skip")
                continue

            if slot not in self.slot_usage_log:
                self.slot_usage_log[slot] = []

            # Append new entries
            self.slot_usage_log[slot].extend(data_list)


    
class Handler():
    def __init__(self, explorer):
        self.explorer = explorer
        # fetch the latest block
        self.b = self.get_block_by_number(self.get_block_number())
        #if create any contract, address start from 0xdddddddddddddddddddddddddddddddddddddddd
        self.create_address = 0xdddddddddddddddddddddddddddddddddddddddd
        self.create_code = {}
    # return result
    def call(self, callinfo, debug=False) -> (dict,list):
        addr = callinfo['address']
        code = None
        code_size = 0
        if addr in self.create_code:
            code = self.create_code[addr]
            code_size = len(code)
        else:
            code = self.explorer.eth_getCode(addr)
            code_size = len(code[2:]) // 2
        callinfo['codesize'] = code_size
        state = EthereumVMstate(self.explorer)
        emul = EthereumSSAEngine(code, self.explorer)
        emul.emulate(callinfo.copy(), state, debug)
        return (emul.get_result(),emul.get_slot_usage(), emul.get_delegate_info())



    def get_extCodeSize(self, addr) -> int:
        code = None
        code_size = 0
        if addr in self.create_code:
            code = self.create_code[addr]
            code_size = len(code)
        else:
            code = self.explorer.eth_getCode(addr)
            code_size = len(code[2:]) // 2
        return code_size

    def get_extCodeHash(self, addr) -> int:
        code = None
        if addr in self.create_code:
            code = self.create_code[addr]
        else:
            code = self.explorer.eth_getCode(addr)
            code = bytes.fromhex(code[2:])
        code_hash = int(keccak(code).hex(),16)
        return code_hash

    def get_balance(self, addr) -> int:
        bal = self.explorer.eth_getBalance(addr)
        return bal

    def get_extCode(self, addr) -> bytes:
        code = None
        if addr in self.create_code:
            code = self.create_code[addr]
        else:
            code = self.explorer.eth_getCode(addr)
            code = bytes.fromhex(code[2:])
        return code

    def get_block_number(self) -> int:
        return self.explorer.eth_blockNumber()

    def get_block_by_number(self, num) -> dict:
        return self.explorer.get_block_by_number(num)

    def get_difficulty(self) -> int:
        return int(self.b['difficulty'],16)

    def get_gas_limit(self) -> int:
        return int(self.b['gasLimit'],16)

    def get_gas_price(self) -> int:
        return self.explorer.eth_gasPrice()

    def create(self, callinfo,  init_bytecode, debug=False):
        callinfo['codesize'] = len(init_bytecode)
        state = EthereumVMstate(self.explorer)
        emul = EthereumSSAEngine(init_bytecode, self.explorer)
        emul.emulate(callinfo.copy(), state, debug)
        result = emul.get_result()
        if result['opcode'] == "RETURN":
            address = self.create_address
            self.create_address += 1
            self.create_code[int_to_address(address)] = result["return_data"]
            return (True, address)
        else:
            return (False, 0)
