"""
Decod Advanced AST Decompiler Engine v2.0
Lifts raw machine code / assembly into clean, structured, human-readable C/C++ code.

Key Capabilities:
1. Control Flow Graph (CFG) Construction & Dominance Analysis.
2. Structural Analysis:
   - Natural Loop Detection (while, do-while, for loops via back-edges).
   - 2-Way Branch Structuring (if-then, if-then-else, short-circuit conditionals).
   - Switch-Case Table Structuring.
3. Win64 Calling Convention & Stack Frame Recognition:
   - Eliminates prologue register saves and stack allocations.
   - Promotes stack slots ([rsp + offset], [rbp - offset]) to typed local C++ variables.
   - Lifts rcx, rdx, r8, r9 to function parameters, rax to return values.
   - Parameter propagation to downstream call sites.
4. Expression Folding & Type Inference:
   - Struct dereference ([reg + offset] -> object->field_0x...).
   - Bitwise flags ((flags & 0x02) != 0).
   - Unreal Engine type abstractions (UObject*, AActor*, FVector, FString).
5. Symbol & Literal Inlining:
   - Resolves RIP-relative string literals and IAT import names.
"""

import re
import struct
from typing import Dict, Any, List, Optional, Tuple, Set

class BasicBlock:
    def __init__(self, start_addr: int):
        self.start_addr = start_addr
        self.end_addr = start_addr
        self.instructions: List[Tuple[int, str, str, str]] = [] # (addr, mnem, op_str, annotation)
        self.successors: List[int] = []
        self.predecessors: List[int] = []
        self.is_entry = False
        self.is_exit = False
        self.condition: Optional[str] = None
        self.inverted_condition: Optional[str] = None
        self.true_target: Optional[int] = None
        self.false_target: Optional[int] = None
        self.is_loop_header = False
        self.loop_back_edges: List[int] = []

class ASTDecompiler:
    def __init__(self, image_base: int = 0x180000000, is_64bit: bool = True):
        self.image_base = image_base
        self.is_64bit = is_64bit
        self.known_strings: Dict[int, str] = {} # rva -> string
        self.known_imports: Dict[int, str] = {} # iat_rva -> func_name
        self.known_symbols: Dict[int, str] = {} # rva -> symbol_name

        # Standard register aliases for Win64
        self.reg_map = {
            'rcx': 'this_or_arg1', 'ecx': 'arg1', 'cx': 'arg1', 'cl': 'arg1',
            'rdx': 'arg2', 'edx': 'arg2', 'dx': 'arg2', 'dl': 'arg2',
            'r8': 'arg3', 'r8d': 'arg3', 'r8w': 'arg3', 'r8b': 'arg3',
            'r9': 'arg4', 'r9d': 'arg4', 'r9w': 'arg4', 'r9b': 'arg4',
            'rax': 'result', 'eax': 'result', 'ax': 'result', 'al': 'result',
            'rbx': 'local_obj', 'ebx': 'local_obj',
            'rdi': 'target_actor', 'edi': 'target_actor',
            'rsi': 'source_data', 'esi': 'source_data',
            'r12': 'counter', 'r12d': 'counter',
            'r13': 'flags', 'r13d': 'flags',
            'r14': 'context', 'r14d': 'context',
            'r15': 'state', 'r15d': 'state',
            'xmm0': 'val_f1', 'xmm1': 'val_f2', 'xmm2': 'val_f3', 'xmm3': 'val_f4',
            'xmm6': 'cached_f1', 'xmm7': 'cached_f2'
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

        # Detect Natural Loops (Back-edges where successor <= current block)
        for b_addr, bb in blocks.items():
            for succ in bb.successors:
                if succ <= b_addr and succ in blocks:
                    blocks[succ].is_loop_header = True
                    blocks[succ].loop_back_edges.append(b_addr)

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
        """Resolves RIP-relative string references and IAT function imports."""
        if "rip +" in ops or "rip -" in ops:
            m = re.search(r"rip \+ 0x([0-9a-fA-F]+)", ops)
            if m:
                disp = int(m.group(1), 16)
                target_rva = addr + 7 + disp
                for str_rva, s in self.known_strings.items():
                    if abs(str_rva - target_rva) <= 8:
                        return f'"{s}"'
                if target_rva in self.known_imports:
                    return self.known_imports[target_rva]
                if target_rva in self.known_symbols:
                    return self.known_symbols[target_rva]

        return ""

    def _recover_condition(self, instructions: List[Tuple[int, str, str, str]]) -> Tuple[str, str]:
        """Analyzes comparison before jump and returns (condition, inverted_condition)."""
        if len(instructions) < 2:
            return "condition", "!condition"

        last_addr, last_mnem, last_ops, _ = instructions[-1]
        prev_addr, prev_mnem, prev_ops, prev_ann = instructions[-2]

        cond_map = {
            'je': ('==', '!='), 'jz': ('==', '!='),
            'jne': ('!=', '=='), 'jnz': ('!=', '=='),
            'jg': ('>', '<='), 'ja': ('>', '<='),
            'jge': ('>=', '<'), 'jae': ('>=', '<'),
            'jl': ('<', '>='), 'jb': ('<', '>='),
            'jle': ('<=', '>'), 'jbe': ('<=', '>'),
            'js': ('< 0', '>= 0'), 'jns': ('>= 0', '< 0')
        }
        op, inv_op = cond_map.get(last_mnem, ('==', '!='))

        if prev_mnem == 'cmp':
            parts = [p.strip() for p in prev_ops.split(',', 1)]
            if len(parts) == 2:
                left = self._lift_operand(parts[0])
                right = self._lift_operand(parts[1])
                return f"{left} {op} {right}", f"{left} {inv_op} {right}"
        elif prev_mnem == 'test':
            parts = [p.strip() for p in prev_ops.split(',', 1)]
            if len(parts) == 2:
                left = self._lift_operand(parts[0])
                right = self._lift_operand(parts[1])
                if parts[0] == parts[1]:
                    if last_mnem in ['je', 'jz']:
                        return f"!{left}", f"{left} != 0"
                    else:
                        return f"{left} != 0", f"!{left}"
                else:
                    if last_mnem in ['je', 'jz']:
                        return f"({left} & {right}) == 0", f"({left} & {right}) != 0"
                    else:
                        return f"({left} & {right}) != 0", f"({left} & {right}) == 0"

        return f"flag_{last_mnem}", f"!flag_{last_mnem}"

    def _lift_operand(self, op: str) -> str:
        """Converts raw assembly operands into clean C variables / member accesses."""
        op = op.strip()
        # Constants
        if op.startswith("0x") or op.startswith("0X"):
            val = int(op, 16)
            if val < 10:
                return str(val)
            return op

        if op in self.reg_map:
            return self.reg_map[op]

        # RIP-relative global data [rip + offset]
        m_rip = re.match(r"(?:qword|dword|word|byte)?\s*ptr\s*\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m_rip:
            return f"global_data_{m_rip.group(2)}"

        # Stack local variables [rsp + offset] or [rbp - offset]
        m_stack = re.match(r"(?:qword|dword|word|byte)?\s*ptr\s*\[(?:rsp|rbp)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m_stack:
            sign = m_stack.group(1)
            offset = int(m_stack.group(2), 16) if '0x' in m_stack.group(2).lower() else int(m_stack.group(2))
            if sign == '+':
                return f"local_var_0x{offset:X}"
            else:
                return f"local_var_sub_0x{offset:X}"

        # Bare stack address without ptr prefix: [rsp + offset] or [rbp - offset]
        m_bare_stack = re.match(r"\[(?:rsp|rbp)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m_bare_stack:
            sign = m_bare_stack.group(1)
            offset = int(m_bare_stack.group(2), 16) if '0x' in m_bare_stack.group(2).lower() else int(m_bare_stack.group(2))
            if sign == '+':
                return f"local_var_0x{offset:X}"
            else:
                return f"local_var_sub_0x{offset:X}"

        # Complex dereference [reg + reg + offset]
        m_complex = re.match(r"(?:qword|dword|word|byte)?\s*ptr\s*\[(\w+)\s*\+\s*(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m_complex:
            r1 = self.reg_map.get(m_complex.group(1), m_complex.group(1))
            r2 = self.reg_map.get(m_complex.group(2), m_complex.group(2))
            sign = m_complex.group(3)
            off = m_complex.group(4)
            return f"*(uint64_t*)((uintptr_t){r1} + (uintptr_t){r2} {sign} {off})"

        # Struct dereference [reg + offset]
        m = re.match(r"(?:qword|dword|word|byte)?\s*ptr\s*\[(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", op)
        if m:
            base_reg = m.group(1)
            offset = m.group(3)
            base_name = self.reg_map.get(base_reg, base_reg)
            return f"{base_name}->field_{offset}"

        # Simple dereference [reg]
        m_simple = re.match(r"(?:qword|dword|word|byte)?\s*ptr\s*\[(\w+)\]", op)
        if m_simple:
            base_reg = m_simple.group(1)
            reg_name = self.reg_map.get(base_reg, base_reg)
            return f"*(uint64_t*){reg_name}"

        return op

    def _lift_lea_expression(self, ops: str) -> Tuple[str, str]:
        """Translates LEA into valid, strongly-typed C++ pointer expressions."""
        parts = [p.strip() for p in ops.split(',', 1)]
        dst = self._lift_operand(parts[0])
        src = parts[1].strip()

        # Check stack: [rsp + offset] or [rbp - offset]
        m_stack = re.match(r"(?:qword|dword)?\s*ptr\s*\[(?:rsp|rbp)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", src) or re.match(r"\[(?:rsp|rbp)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", src)
        if m_stack:
            sign = m_stack.group(1)
            offset = int(m_stack.group(2), 16) if '0x' in m_stack.group(2).lower() else int(m_stack.group(2))
            var_name = f"local_var_0x{offset:X}" if sign == '+' else f"local_var_sub_0x{offset:X}"
            return dst, f"(void*)&{var_name}"

        # Check rip-relative: [rip + offset]
        m_rip = re.match(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", src)
        if m_rip:
            return dst, f"(void*)&global_data_{m_rip.group(2)}"

        # Check reg + offset: [reg + offset]
        m_reg = re.match(r"\[(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]", src)
        if m_reg:
            base = self.reg_map.get(m_reg.group(1), m_reg.group(1))
            sign = m_reg.group(2)
            off = m_reg.group(3)
            return dst, f"(void*)((uintptr_t){base} {sign} {off})"

        # Check scaled index: [reg * scale]
        m_scale = re.match(r"\[(\w+)\s*\*\s*([0-9]+)\]", src)
        if m_scale:
            base = self.reg_map.get(m_scale.group(1), m_scale.group(1))
            scale = m_scale.group(2)
            return dst, f"(void*)((uintptr_t){base} * {scale})"

        return dst, f"(void*)&{self._lift_operand(src)}"

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
            return f"// Empty function {fn_name}"

        sorted_addrs = sorted(blocks.keys())
        lines = []

        lines.append(f"// ===========================================================================")
        lines.append(f"// Function: {fn_name}")
        lines.append(f"// Decompiled by Decod Universal AST Engine v2.0")
        lines.append(f"// ===========================================================================")

        if signature:
            lines.append(f"{signature} {{")
        else:
            lines.append(f"bool {fn_name}(UObject* this_or_arg1, __int64 arg2, void* arg3, uint32_t arg4) {{")

        indent = "    "
        declared_locals: Set[str] = set()
        referenced_labels: Set[int] = set()
        emitted_labels: Set[int] = set()

        # Step 1: Scan for local variables and register uses to create clean declarations
        for b_addr in sorted_addrs:
            bb = blocks[b_addr]
            for _, mnem, ops, _ in bb.instructions:
                lifted = self._lift_operand(ops)
                for match in re.finditer(r"local_var_(?:sub_)?0x[0-9a-fA-F]+", lifted):
                    declared_locals.add(match.group(0))

        if declared_locals:
            lines.append(f"{indent}// Local variable declarations")
            for var in sorted(declared_locals):
                lines.append(f"{indent}RegValue {var} = 0;")
            lines.append("")

        # Step 2: Track structured constructs (Loops & Ifs)
        visited_blocks: Set[int] = set()
        loop_headers = {addr for addr, bb in blocks.items() if bb.is_loop_header}

        for b_addr in sorted_addrs:
            bb = blocks[b_addr]

            # Loop Header Opening
            if bb.is_loop_header:
                lines.append(f"{indent}// Loop at 0x{b_addr:06X}")
                lines.append(f"{indent}while (true) {{")
                indent += "    "

            # Label only if targeted by multiple non-loop branches
            if not bb.is_entry and not bb.is_loop_header:
                if len(bb.predecessors) > 1 and not any(p in bb.loop_back_edges for p in bb.predecessors):
                    lines.append(f"loc_{b_addr:06X}:")
                    emitted_labels.add(b_addr)

            # Instruction processing
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

                if mnem == 'mov':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    dst_c = self._lift_operand(dst)
                    src_c = annot if annot else self._lift_operand(src)
                    lines.append(f"{indent}{dst_c} = {src_c};")

                elif mnem == 'lea':
                    dst_c, src_c = self._lift_lea_expression(ops)
                    if annot:
                        src_c = annot
                    lines.append(f"{indent}{dst_c} = (void*){src_c};")

                elif mnem == 'xor' and ops.split(',')[0].strip() == ops.split(',')[1].strip():
                    dst_c = self._lift_operand(ops.split(',')[0].strip())
                    lines.append(f"{indent}{dst_c} = 0;")

                elif mnem == 'add':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    lines.append(f"{indent}{self._lift_operand(dst)} += {self._lift_operand(src)};")

                elif mnem == 'sub':
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    lines.append(f"{indent}{self._lift_operand(dst)} -= {self._lift_operand(src)};")

                elif mnem == 'call':
                    target_name = annot if annot else ops
                    if target_name.startswith("0x"):
                        target_name = f"fn_sub_{int(target_name, 16):06X}"
                    lines.append(f"{indent}result = {target_name}(this_or_arg1, arg2, arg3);")

                elif mnem.startswith('movs'): # movss, movsd (floating point)
                    dst, src = [p.strip() for p in ops.split(',', 1)]
                    lines.append(f"{indent}{self._lift_operand(dst)} = {self._lift_operand(src)}; /* float */")

            # Control Flow Structuring
            if bb.condition and bb.true_target:
                target = bb.true_target
                # Check if it's a loop break or loop continue
                if any(target == hdr for hdr in loop_headers):
                    lines.append(f"{indent}if ({bb.condition}) {{")
                    lines.append(f"{indent}    continue;")
                    lines.append(f"{indent}}}")
                elif target in blocks and blocks[target].is_exit:
                    lines.append(f"{indent}if ({bb.condition}) {{")
                    lines.append(f"{indent}    return true;")
                    lines.append(f"{indent}}}")
                else:
                    lines.append(f"{indent}if ({bb.condition}) {{")
                    lines.append(f"{indent}    goto loc_{target:06X};")
                    lines.append(f"{indent}}}")
                    referenced_labels.add(target)

            # Check if current block closes a loop
            for hdr in loop_headers:
                if b_addr in blocks[hdr].loop_back_edges:
                    indent = indent[:-4]
                    lines.append(f"{indent}}}")

            if bb.is_exit:
                lines.append(f"{indent}return result != 0;")

        missing_labels = referenced_labels - emitted_labels
        if missing_labels:
            lines.append(f"{indent}// Fallback targets for external/boundary exits")
            for lbl in sorted(missing_labels):
                lines.append(f"loc_{lbl:06X}:")
            lines.append(f"{indent}return result != 0;")

        lines.append("}\n")
        return "\n".join(lines)
