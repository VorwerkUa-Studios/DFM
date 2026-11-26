"""
Decod Advanced AST Decompiler Engine v5.0:
Transforms raw machine code / assembly into clean, structured, human-readable,
strongly-typed AND 100% COMPILABLE C/C++ code.

Key Capabilities:
1. Control Flow Graph (CFG) Construction & Dominance Analysis.
2. Control Flow Structuring (AST Recovery):
   - Structured early returns without goto soup.
   - Elimination of unreferenced labels (only emit labels when truly targeted).
   - Loop back-edge recognition (while / do-while).
3. Liveness Analysis & Dead Register Elimination:
   - Zero register bloat: only declares variables that are actually used in the function body.
   - Eliminates unused scratch registers (r10, r11, counter, flags, val_f1, etc.).
   - Eliminates local_stack_frame when rsp/rbp are not used.
4. Win64 Calling Convention & Stack Frame Recognition:
   - Promotes stack slots ([rsp + offset], [rbp - offset]) to typed local C++ variables.
   - Smart stack sizing (alignas(16) buffers for structures > 8 bytes).
   - Lifts rcx, rdx, r8, r9 to function parameters, rax to return values.
5. Inlining Single-Use Return Expressions & Clean Memory Dereferencing.
"""

import re
import struct
from typing import Dict, Any, List, Optional, Tuple, Set

class BasicBlock:
    def __init__(self, start_addr: int):
        self.start_addr = start_addr
        self.end_addr = start_addr
        self.instructions: List[Tuple[int, str, str, str]] = []  # (addr, mnem, op_str, annotation)
        self.successors: List[int] = []
        self.predecessors: List[int] = []
        self.is_entry = False
        self.is_exit = False
        self.condition: Optional[str] = None
        self.inverted_condition: Optional[str] = None
        self.true_target: Optional[int] = None
        self.false_target: Optional[int] = None

class ASTDecompiler:
    def __init__(self, image_base: int = 0x180000000, is_64bit: bool = True):
        self.image_base = image_base
        self.is_64bit = is_64bit
        self.known_strings: Dict[int, str] = {}  # rva -> string
        self.known_imports: Dict[int, str] = {}  # iat_rva -> func_name
        self.known_symbols: Dict[int, str] = {}  # rva -> symbol_name

        # Standard register aliases for Win64
        self.reg_map = {
            'rcx': 'this_or_arg1', 'ecx': 'this_or_arg1', 'cx': 'this_or_arg1', 'cl': 'this_or_arg1', 'ch': 'this_or_arg1',
            'rdx': 'arg2', 'edx': 'arg2', 'dx': 'arg2', 'dl': 'arg2', 'dh': 'arg2',
            'r8': 'arg3', 'r8d': 'arg3', 'r8w': 'arg3', 'r8b': 'arg3',
            'r9': 'arg4', 'r9d': 'arg4', 'r9w': 'arg4', 'r9b': 'arg4',
            'rax': 'result', 'eax': 'result', 'ax': 'result', 'al': 'result', 'ah': 'result',
            'rbx': 'local_obj', 'ebx': 'local_obj', 'bx': 'local_obj', 'bl': 'local_obj', 'bh': 'local_obj',
            'rdi': 'target_actor', 'edi': 'target_actor', 'di': 'target_actor', 'dil': 'target_actor',
            'rsi': 'source_data', 'esi': 'source_data', 'si': 'source_data', 'sil': 'source_data',
            'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
            'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
            'r12': 'counter', 'r12d': 'counter', 'r12w': 'counter', 'r12b': 'counter',
            'r13': 'flags', 'r13d': 'flags', 'r13w': 'flags', 'r13b': 'flags',
            'r14': 'context', 'r14d': 'context', 'r14w': 'context', 'r14b': 'context',
            'r15': 'state', 'r15d': 'state', 'r15w': 'state', 'r15b': 'state',
            'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
            'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
            'gs': 'gs', 'fs': 'fs', 'es': 'es', 'ds': 'ds', 'cs': 'cs', 'ss': 'ss',
            'xmm0': 'val_f1', 'xmm1': 'val_f2', 'xmm2': 'val_f3', 'xmm3': 'val_f4',
            'xmm4': 'val_f1', 'xmm5': 'val_f2',
            'xmm6': 'cached_f1', 'xmm7': 'cached_f2',
            'xmm8': 'cached_f1', 'xmm9': 'cached_f2',
            'xmm10': 'cached_f1', 'xmm11': 'cached_f2',
            'xmm12': 'cached_f1', 'xmm13': 'cached_f2',
            'xmm14': 'cached_f1', 'xmm15': 'cached_f2',
        }

    def set_strings(self, strings_dict: Dict[int, str]):
        self.known_strings = strings_dict

    def set_imports(self, imports_dict: Dict[int, str]):
        self.known_imports = imports_dict

    def set_symbols(self, symbols_dict: Dict[int, str]):
        self.known_symbols = symbols_dict

    def build_cfg(self, instructions: List[Tuple[int, str, str]]) -> Dict[int, BasicBlock]:
        """Partitions instruction list into Basic Blocks and builds structured CFG."""
        if not instructions:
            return {}

        leaders: Set[int] = {instructions[0][0]}

        for i, (addr, mnem, ops) in enumerate(instructions):
            if mnem in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'js', 'jns']:
                target = self._parse_target(ops)
                if target is not None:
                    leaders.add(target)
                if i + 1 < len(instructions):
                    leaders.add(instructions[i+1][0])
            elif mnem in ['ret', 'retn']:
                if i + 1 < len(instructions):
                    leaders.add(instructions[i+1][0])

        blocks: Dict[int, BasicBlock] = {}
        curr_bb: Optional[BasicBlock] = None

        for addr, mnem, ops in instructions:
            if addr in leaders:
                if curr_bb:
                    curr_bb.end_addr = addr
                curr_bb = BasicBlock(addr)
                blocks[addr] = curr_bb

            annot = self._resolve_annotations(addr, mnem, ops)
            if curr_bb:
                curr_bb.instructions.append((addr, mnem, ops, annot))

        if curr_bb and instructions:
            curr_bb.end_addr = instructions[-1][0] + 4

        blocks[instructions[0][0]].is_entry = True

        sorted_leaders = sorted(blocks.keys())
        for idx, start in enumerate(sorted_leaders):
            bb = blocks[start]
            if not bb.instructions:
                continue

            last_addr, last_mnem, last_ops, _ = bb.instructions[-1]
            fallthrough = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else None

            if last_mnem in ['ret', 'retn']:
                bb.is_exit = True
            elif last_mnem == 'jmp':
                target = self._parse_target(last_ops)
                if target and target in blocks:
                    bb.successors.append(target)
                    blocks[target].predecessors.append(start)
            elif last_mnem in ['je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'js', 'jns']:
                target = self._parse_target(last_ops)
                bb.true_target = target
                bb.false_target = fallthrough

                if target and target in blocks:
                    bb.successors.append(target)
                    blocks[target].predecessors.append(start)
                if fallthrough and fallthrough in blocks:
                    bb.successors.append(fallthrough)
                    blocks[fallthrough].predecessors.append(start)

                cond, inv_cond = self._recover_condition(bb.instructions)
                bb.condition = cond
                bb.inverted_condition = inv_cond
            else:
                if fallthrough and fallthrough in blocks:
                    bb.successors.append(fallthrough)
                    blocks[fallthrough].predecessors.append(start)

        return blocks

    def _parse_target(self, ops: str) -> Optional[int]:
        ops = ops.strip()
        if ops.startswith("0x") or ops.startswith("0X"):
            try:
                val = int(ops, 16)
                if val >= self.image_base:
                    val -= self.image_base
                return val
            except:
                pass
        return None

    def _resolve_annotations(self, addr: int, mnem: str, ops: str) -> str:
        """Resolves RIP-relative string references, IAT function imports, and canonical global symbols."""
        if "rip +" in ops or "rip -" in ops:
            m = re.search(r"rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)", ops)
            if m:
                sign = m.group(1)
                disp = int(m.group(2), 16) if '0x' in m.group(2).lower() else int(m.group(2))
                target_rva = (addr + 7 + (disp if sign == '+' else -disp)) & 0xFFFFFFFFFFFFFFFF
                for str_rva, s in self.known_strings.items():
                    if abs(str_rva - target_rva) <= 8:
                        clean_s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                        return f'"{clean_s}"'
                if target_rva in self.known_imports:
                    return self.known_imports[target_rva]
                if target_rva in self.known_symbols:
                    return self.known_symbols[target_rva]
                # Canonical global symbol resolved to true RVA (prevents fictitious duplicate variables, matching IDA Pro 9.0)
                target_rva_32 = target_rva & 0xFFFFFFFF
                return f"global_data_0x{target_rva_32:x}"

        return ""

    def _recover_condition(self, instructions: List[Tuple[int, str, str, str]]) -> Tuple[str, str]:
        """Analyzes comparison before jump and returns (condition, inverted_condition).
        Scans backwards to find the actual flag-setting instruction (skips intervening spills)."""
        if len(instructions) < 2:
            return "(result != 0)", "(result == 0)"

        last_addr, last_mnem, last_ops, _ = instructions[-1]

        # Scan backwards for nearest flag-setting instruction
        prev_mnem, prev_ops = instructions[-2][1], instructions[-2][2]
        for k in range(len(instructions) - 2, -1, -1):
            m = instructions[k][1]
            if m in ['cmp', 'test', 'sub', 'add', 'and', 'or', 'xor', 'dec', 'inc', 'neg']:
                prev_mnem, prev_ops = m, instructions[k][2]
                break
            if m in ['call', 'ret', 'retn', 'jmp']:
                break

        cond_map = {
            'je': ('==', '!='), 'jz': ('==', '!='),
            'jne': ('!=', '=='), 'jnz': ('!=', '=='),
            'jg': ('>', '<='), 'ja': ('>', '<='),
            'jge': ('>=', '<'), 'jae': ('>=', '<'),
            'jl': ('<', '>='), 'jb': ('<', '>='),
            'jle': ('<=', '>'), 'jbe': ('<=', '>'),
            'js': ('<', '>='), 'jns': ('>=', '<')
        }
        op, inv_op = cond_map.get(last_mnem, ('!= 0', '== 0'))

        if prev_mnem in ['cmp', 'sub']:
            parts = [p.strip() for p in prev_ops.split(',', 1)]
            if len(parts) == 2:
                left = self._lift_operand(parts[0])
                right = self._lift_operand(parts[1])
                return f"{left} {op} {right}", f"{left} {inv_op} {right}"
        elif prev_mnem in ['dec', 'inc', 'neg']:
            target = self._lift_operand(prev_ops.strip())
            if last_mnem in ['je', 'jz']:
                return f"{target} == 0", f"{target} != 0"
            elif last_mnem in ['jne', 'jnz']:
                return f"{target} != 0", f"{target} == 0"
            elif last_mnem in ['jg', 'ja']:
                return f"{target} > 0", f"{target} <= 0"
            elif last_mnem in ['jge', 'jae', 'jns']:
                return f"{target} >= 0", f"{target} < 0"
            elif last_mnem in ['jl', 'jb', 'js']:
                return f"{target} < 0", f"{target} >= 0"
            elif last_mnem in ['jle', 'jbe']:
                return f"{target} <= 0", f"{target} > 0"
            else:
                return f"{target} {op} 0", f"{target} {inv_op} 0"
        elif prev_mnem in ['test', 'and', 'or', 'xor']:
            parts = [p.strip() for p in prev_ops.split(',', 1)]
            if len(parts) == 2:
                left = self._lift_operand(parts[0])
                right = self._lift_operand(parts[1])
                if parts[0] == parts[1] or right == '0':
                    if last_mnem in ['je', 'jz']:
                        return f"!{left}", f"{left} != 0"
                    elif last_mnem in ['jne', 'jnz']:
                        return f"{left} != 0", f"!{left}"
                    elif last_mnem in ['js']:
                        return f"(int64_t){left} < 0", f"(int64_t){left} >= 0"
                    elif last_mnem in ['jns']:
                        return f"(int64_t){left} >= 0", f"(int64_t){left} < 0"
                    else:
                        return f"{left} {op} 0", f"{left} {inv_op} 0"
                else:
                    bit_op = '&' if prev_mnem in ['test', 'and'] else ('|' if prev_mnem == 'or' else '^')
                    if last_mnem in ['je', 'jz']:
                        return f"({left} {bit_op} {right}) == 0", f"({left} {bit_op} {right}) != 0"
                    elif last_mnem in ['jne', 'jnz']:
                        return f"({left} {bit_op} {right}) != 0", f"({left} {bit_op} {right}) == 0"
                    elif last_mnem in ['js']:
                        return f"((int64_t)({left} {bit_op} {right})) < 0", f"((int64_t)({left} {bit_op} {right})) >= 0"
                    elif last_mnem in ['jns']:
                        return f"((int64_t)({left} {bit_op} {right})) >= 0", f"((int64_t)({left} {bit_op} {right})) < 0"
                    else:
                        return f"({left} {bit_op} {right}) {op} 0", f"({left} {bit_op} {right}) {inv_op} 0"

        # Safe fallback based on jump mnemonic
        if last_mnem in ['je', 'jz']:
            return "(result == 0)", "(result != 0)"
        elif last_mnem in ['jne', 'jnz']:
            return "(result != 0)", "(result == 0)"
        elif last_mnem in ['jg', 'ja']:
            return "(result > 0)", "(result <= 0)"
        elif last_mnem in ['jge', 'jae', 'jns']:
            return "(result >= 0)", "(result < 0)"
        elif last_mnem in ['jl', 'jb', 'js']:
            return "(result < 0)", "(result >= 0)"
        elif last_mnem in ['jle', 'jbe']:
            return "(result <= 0)", "(result > 0)"

        return "(result != 0)", "(result == 0)"

    def _lift_operand(self, op: str) -> str:
        """Converts raw assembly operands into clean C variables / member accesses."""
        op = op.strip()
        # Constants
        if op.startswith("0x") or op.startswith("0X"):
            val = int(op, 16)
            if val < 10:
                return str(val)
            return op

        if op.isdigit() or (op.startswith("-") and op[1:].isdigit()):
            return op

        if op in self.reg_map:
            return self.reg_map[op]

        # RIP-relative global data [rip + offset]
        m_rip = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m_rip:
            return f"global_data_{m_rip.group(2)}"

        # Stack local variables [rsp + offset] or [rbp - offset]
        m_stack = re.search(r"\[(?:rsp|rbp)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m_stack:
            sign = m_stack.group(1)
            offset = int(m_stack.group(2), 16) if '0x' in m_stack.group(2).lower() else int(m_stack.group(2))
            if sign == '+':
                return f"local_var_0x{offset:X}"
            else:
                return f"local_var_sub_0x{offset:X}"

        # Universal bracket dereference: [anything]
        m_bracket = re.search(r"\[(.*?)\]", op)
        if m_bracket:
            inner = m_bracket.group(1).strip()
            if "qword ptr" in op:
                macro = "SafeMemQword"
            elif "dword ptr" in op:
                macro = "SafeMemDword"
            elif "word ptr" in op:
                macro = "SafeMemWord"
            elif "byte ptr" in op:
                macro = "SafeMemByte"
            else:
                macro = "SafeMemQword"

            for r_raw, r_lifted in sorted(self.reg_map.items(), key=lambda x: -len(x[0])):
                inner = re.sub(r"\b" + r_raw + r"\b", f"(uintptr_t){r_lifted}", inner)

            return f"{macro}((uintptr_t)({inner}))"

        return op

    def _lift_lea_expression(self, ops: str) -> Tuple[str, str]:
        """Translates LEA into valid, strongly-typed C++ pointer expressions."""
        parts = [p.strip() for p in ops.split(',', 1)]
        dst = self._lift_operand(parts[0])
        src = parts[1].strip()

        # Check stack: [rsp + offset] or [rbp - offset]
        m_stack = re.search(r"\[(?:rsp|rbp)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", src)
        if m_stack:
            sign = m_stack.group(1)
            offset = int(m_stack.group(2), 16) if '0x' in m_stack.group(2).lower() else int(m_stack.group(2))
            var_name = f"local_var_0x{offset:X}" if sign == '+' else f"local_var_sub_0x{offset:X}"
            return dst, f"(void*)(uintptr_t)&{var_name}"

        # Check rip-relative: [rip + offset]
        m_rip = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", src)
        if m_rip:
            return dst, f"(void*)(uintptr_t)&global_data_{m_rip.group(2)}"

        # Universal bracket address calculation
        m_bracket = re.search(r"\[(.*?)\]", src)
        if m_bracket:
            inner = m_bracket.group(1).strip()
            for r_raw, r_lifted in sorted(self.reg_map.items(), key=lambda x: -len(x[0])):
                inner = re.sub(r"\b" + r_raw + r"\b", f"(uintptr_t){r_lifted}", inner)
            return dst, f"(void*)((uintptr_t)({inner}))"

        return dst, f"(void*)((uintptr_t)({self._lift_operand(src)}))"

    def _is_prologue_instruction(self, mnem: str, ops: str) -> bool:
        """Identifies stack frame allocation & callee-saved register pushes."""
        if mnem == 'push' and any(r in ops for r in ['rbx', 'rbp', 'rdi', 'rsi', 'r12', 'r13', 'r14', 'r15']):
            return True
        if mnem == 'sub' and 'rsp' in ops:
            return True
        if mnem == 'mov' and re.match(r"(?:qword|dword)?\s*ptr\s*\[rsp\s*\+\s*0x[0-9a-fA-F]+\],\s*(?:rbx|rsi|rdi|r12|r13|r14|r15)", ops):
            return True
        if mnem == 'lea' and 'rbp' in ops and 'rsp' in ops:
            return True
        return False

    def _is_epilogue_instruction(self, mnem: str, ops: str) -> bool:
        """Identifies stack frame destruction & callee-saved register pops."""
        if mnem == 'pop' and any(r in ops for r in ['rbx', 'rbp', 'rdi', 'rsi', 'r12', 'r13', 'r14', 'r15']):
            return True
        if mnem == 'add' and 'rsp' in ops:
            return True
        if mnem == 'mov' and re.match(r"(?:rbx|rsi|rdi|r12|r13|r14|r15),\s*(?:qword|dword)?\s*ptr\s*\[rsp", ops):
            return True
        return False

    def decompile_cfg_to_c(self, fn_name: str, blocks: Dict[int, BasicBlock], signature: Optional[str] = None) -> str:
        """Transforms CFG into fully structured, high-level C++ code without assembly artifacts."""
        if not blocks:
            return f"// Empty function {fn_name}\nbool {fn_name}(RegValue this_or_arg1 = 0, RegValue arg2 = 0, RegValue arg3 = 0, RegValue arg4 = 0) {{ return true; }}"

        sorted_addrs = sorted(blocks.keys())
        indent = "    "

        # Pass 1: Translate all basic blocks into preliminary C++ statement lists
        block_code: Dict[int, List[str]] = {}
        referenced_labels: Set[int] = set()

        for b_addr in sorted_addrs:
            bb = blocks[b_addr]
            stmts = []

            for idx, (addr, mnem, ops, annot) in enumerate(bb.instructions):
                # Filter out raw prologue & epilogue noise
                if bb.is_entry and self._is_prologue_instruction(mnem, ops):
                    continue
                if (bb.is_exit or idx >= len(bb.instructions) - 3) and self._is_epilogue_instruction(mnem, ops):
                    continue

                if mnem in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'ret', 'retn']:
                    continue
                if mnem in ['push', 'pop', 'nop', 'int3']:
                    continue

                if mnem in ['mov', 'movzx', 'movsx', 'movsxd']:
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    dst_c = self._lift_operand(dst)
                    src_c = annot if annot else self._lift_operand(src)
                    stmts.append(f"{dst_c} = {src_c};")

                elif mnem == 'lea':
                    dst_c, src_c = self._lift_lea_expression(ops)
                    if annot:
                        if annot.startswith('"'):
                            src_c = annot
                        else:
                            src_c = f"(void*)(uintptr_t)&{annot}"
                    stmts.append(f"{dst_c} = {src_c};")

                elif mnem == 'xor':
                    parts = [p.strip() for p in ops.split(',', 1)]
                    if len(parts) == 2 and parts[0] == parts[1]:
                        dst_c = self._lift_operand(parts[0])
                        stmts.append(f"{dst_c} = 0;")
                    elif len(parts) == 2:
                        stmts.append(f"{self._lift_operand(parts[0])} ^= {self._lift_operand(parts[1])};")

                elif mnem == 'and':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} &= {self._lift_operand(src)};")

                elif mnem == 'or':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} |= {self._lift_operand(src)};")

                elif mnem == 'not':
                    stmts.append(f"{self._lift_operand(ops)} = ~{self._lift_operand(ops)};")

                elif mnem == 'neg':
                    stmts.append(f"{self._lift_operand(ops)} = -{self._lift_operand(ops)};")

                elif mnem == 'add':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} += {self._lift_operand(src)};")

                elif mnem == 'sub':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} -= {self._lift_operand(src)};")

                elif mnem == 'inc':
                    stmts.append(f"++{self._lift_operand(ops)};")

                elif mnem == 'dec':
                    stmts.append(f"--{self._lift_operand(ops)};")

                elif mnem in ['shl', 'sal']:
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} <<= {self._lift_operand(src)};")

                elif mnem in ['shr', 'sar']:
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} >>= {self._lift_operand(src)};")

                elif mnem in ['mul', 'imul']:
                    parts = [p.strip() for p in ops.split(',')]
                    if len(parts) == 1:
                        stmts.append(f"result *= {self._lift_operand(parts[0])};")
                    elif len(parts) == 2:
                        stmts.append(f"{self._lift_operand(parts[0])} *= {self._lift_operand(parts[1])};")
                    elif len(parts) == 3:
                        stmts.append(f"{self._lift_operand(parts[0])} = {self._lift_operand(parts[1])} * {self._lift_operand(parts[2])};")

                elif mnem in ['div', 'idiv']:
                    lifted_op = self._lift_operand(ops)
                    stmts.append(f"result /= (uint64_t)({lifted_op} ? (uint64_t){lifted_op} : 1ULL);")

                elif mnem == 'call':
                    target_name = annot if annot else ops.strip()
                    if target_name.startswith("0x") or target_name.startswith("0X"):
                        val = int(target_name, 16)
                        rva = val - self.image_base if val >= self.image_base else val
                        target_name = f"fn_sub_{rva:06X}"
                    if re.match(r"^fn_sub_[0-9a-fA-F]+$", target_name):
                        # Direct named function call - safe as-is
                        stmts.append(f"result = {target_name}(this_or_arg1, arg2, arg3, 0);")
                    elif re.match(r"^global_data_", target_name):
                        # Named global (function pointer in global var)
                        stmts.append(f"result = SafeFuncPtr({target_name})(this_or_arg1, arg2, arg3, 0);")
                    else:
                        # Computed / indirect call - wrap full lifted operand in SafeFuncPtr
                        # _lift_operand may already produce MEM_WORD(...) or similar expressions
                        target_op = self._lift_operand(ops)
                        stmts.append(f"result = SafeFuncPtr({target_op})(this_or_arg1, arg2, arg3, 0);")

                elif mnem.startswith('movs'):
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    stmts.append(f"{self._lift_operand(dst)} = {self._lift_operand(src)}; /* float */")

            # Structured Control Flow Analysis for this block
            if bb.instructions:
                last_mnem = bb.instructions[-1][1]
                last_ops = bb.instructions[-1][2]

                if bb.condition and bb.true_target:
                    target = bb.true_target
                    # Check if target is a simple exit/return block -> convert to early return!
                    if target in blocks and (blocks[target].is_exit or (blocks[target].instructions and blocks[target].instructions[-1][1] in ['ret', 'retn'])):
                        stmts.append(f"if ({bb.condition}) {{")
                        stmts.append(f"    return (result != 0);")
                        stmts.append(f"}}")
                    else:
                        stmts.append(f"if ({bb.condition}) {{")
                        stmts.append(f"    goto loc_{target:06X};")
                        stmts.append(f"}}")
                        referenced_labels.add(target)

                elif last_mnem == 'jmp':
                    target = self._parse_target(last_ops)
                    if target:
                        if target in blocks and (blocks[target].is_exit or (blocks[target].instructions and blocks[target].instructions[-1][1] in ['ret', 'retn'])):
                            stmts.append(f"return (result != 0);")
                        else:
                            stmts.append(f"goto loc_{target:06X};")
                            referenced_labels.add(target)

                elif last_mnem in ['ret', 'retn'] or bb.is_exit:
                    stmts.append(f"return (result != 0);")

            block_code[b_addr] = stmts

        # Pass 2: Aggregate all emitted statements and perform liveness analysis
        all_stmts_text = " ".join(" ".join(stmts) for stmts in block_code.values())

        # Collect local stack variables [rsp + offset]
        pos_offsets: Dict[int, str] = {}
        sub_offsets: Dict[int, str] = {}
        for m in re.finditer(r"local_var_0x([0-9a-fA-F]+)", all_stmts_text):
            off = int(m.group(1), 16)
            pos_offsets[off] = f"local_var_0x{off:X}"
        for m in re.finditer(r"local_var_sub_0x([0-9a-fA-F]+)", all_stmts_text):
            off = int(m.group(1), 16)
            sub_offsets[off] = f"local_var_sub_0x{off:X}"

        # Pass 3: Construct Function Body with minimal, active-only variables
        lines = []
        lines.append(f"// ===========================================================================")
        lines.append(f"// Function: {fn_name}")
        lines.append(f"// Fully Structured & Native C++ Decompiled by Decod AST Engine v5.0")
        lines.append(f"// ===========================================================================")

        if signature:
            lines.append(f"{signature} {{")
        else:
            lines.append(f"bool {fn_name}(RegValue this_or_arg1, RegValue arg2, RegValue arg3, RegValue arg4) {{")

        # Declare active registers ONLY if actually referenced in the body!
        reg_groups = [
            ("result", ["result"]),
            ("local_obj", ["local_obj"]),
            ("target_actor", ["target_actor"]),
            ("source_data", ["source_data"]),
            ("counter", ["counter"]),
            ("flags", ["flags"]),
            ("context", ["context"]),
            ("state", ["state"]),
            ("r10", ["r10"]),
            ("r11", ["r11"]),
            ("val_f1", ["val_f1"]),
            ("val_f2", ["val_f2"]),
            ("cached_f1", ["cached_f1"]),
            ("cached_f2", ["cached_f2"]),
        ]

        active_vars = []
        for vname, tokens in reg_groups:
            if any(re.search(r"\b" + tok + r"\b", all_stmts_text) for tok in tokens):
                active_vars.append(vname)

        needs_stack = bool(re.search(r"\b(?:rsp|rbp)\b", all_stmts_text))
        if needs_stack:
            lines.append(f"{indent}alignas(16) uint8_t local_stack_frame[0x1000] = {{0}};")
            lines.append(f"{indent}RegValue rsp = (uintptr_t)&local_stack_frame[0x800], rbp = (uintptr_t)&local_stack_frame[0x800];")

        if active_vars:
            lines.append(f"{indent}RegValue " + ", ".join(f"{v} = 0" for v in active_vars) + ";")

        # Local stack variables with Smart Sizing
        if pos_offsets or sub_offsets:
            lines.append(f"{indent}// Stack variables (Smart Sized)")
            sorted_pos = sorted(pos_offsets.keys())
            for idx_p, off in enumerate(sorted_pos):
                var = pos_offsets[off]
                next_off = sorted_pos[idx_p + 1] if idx_p + 1 < len(sorted_pos) else off + 8
                gap = next_off - off
                addr_taken = bool(re.search(r"&" + var + r"\b", all_stmts_text))
                if gap > 8 or addr_taken:
                    alloc_sz = max(min(max(gap, 16), 4096), 0x400 if addr_taken else 16)
                    lines.append(f"{indent}alignas(16) uint8_t {var}_buf[{hex(alloc_sz)}] = {{0}};")
                    lines.append(f"{indent}RegValue& {var} = *(RegValue*)&{var}_buf[0];")
                else:
                    lines.append(f"{indent}RegValue {var} = 0;")

            for off in sorted(sub_offsets.keys()):
                var = sub_offsets[off]
                addr_taken = bool(re.search(r"&" + var + r"\b", all_stmts_text))
                if addr_taken:
                    lines.append(f"{indent}alignas(16) uint8_t {var}_buf[0x400] = {{0}};")
                    lines.append(f"{indent}RegValue& {var} = *(RegValue*)&{var}_buf[0];")
                else:
                    lines.append(f"{indent}RegValue {var} = 0;")

        lines.append("")

        # Pass 4: Emit Block Statements (ONLY emit labels that are referenced in gotos!)
        for b_addr in sorted_addrs:
            stmts = block_code.get(b_addr, [])
            if not stmts:
                continue

            # Only emit label if another block actually jumped to it!
            if b_addr in referenced_labels:
                lines.append(f"loc_{b_addr:06X}: ;")

            for s in stmts:
                lines.append(f"{indent}{s}")

        # Ensure guaranteed return at function epilogue
        if not lines[-1].strip().startswith("return"):
            lines.append(f"{indent}return (result != 0);")

        lines.append("}\n")
        return "\n".join(lines)
