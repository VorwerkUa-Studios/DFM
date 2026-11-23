import unittest
from tools.decompiler.semantic_lifter import SemanticLifter
from tools.decompiler.ast_decompiler import ASTDecompiler
from tools.decompiler.domain_clusterer import DomainClusterer

class TestDecompilerV5(unittest.TestCase):
    def test_semantic_lifter_trivial_stubs(self):
        lifter = SemanticLifter()
        # NOP stub
        res = lifter.analyze_function_semantics(0x1000, [(0x1000, 'ret', '')], [], [])
        self.assertIsNotNone(res)
        self.assertIn("return true;", res.native_body)

        # Return false
        res = lifter.analyze_function_semantics(0x1000, [(0x1000, 'xor', 'eax, eax'), (0x1002, 'ret', '')], [], [])
        self.assertIsNotNone(res)
        self.assertIn("return false;", res.native_body)

        # Return true
        res = lifter.analyze_function_semantics(0x1000, [(0x1000, 'mov', 'eax, 1'), (0x1005, 'ret', '')], [], [])
        self.assertIsNotNone(res)
        self.assertIn("return true;", res.native_body)

        # Getter
        res = lifter.analyze_function_semantics(0x1000, [(0x1000, 'mov', 'rax, qword ptr [rcx + 0x28]'), (0x1004, 'ret', '')], [], [])
        self.assertIsNotNone(res)
        self.assertIn("0x28", res.native_body)

        # Setter
        res = lifter.analyze_function_semantics(0x1000, [(0x1000, 'mov', 'qword ptr [rcx + 0x30], rdx'), (0x1004, 'ret', '')], [], [])
        self.assertIsNotNone(res)
        self.assertIn("0x30", res.native_body)

    def test_semantic_lifter_game_gates(self):
        lifter = SemanticLifter()
        # DLC Gate
        res = lifter.analyze_function_semantics(0x3C030, [(0x3C030, 'ret', '')], ["DLC content is locked"], [])
        self.assertIsNotNone(res)
        self.assertIn("return false;", res.native_body)

        # Foliage 300 Limit Gate
        res = lifter.analyze_function_semantics(0x1714A8, [(0x1714A8, 'cmp', 'eax, 300'), (0x1714AD, 'ret', '')], [], [])
        self.assertIsNotNone(res)
        self.assertIn("0x7FFFFFFF", res.native_body)

    def test_ast_decompiler_liveness(self):
        dec = ASTDecompiler()
        insns = [
            (0x1000, 'mov', 'rax, rcx'),
            (0x1003, 'add', 'rax, rdx'),
            (0x1006, 'ret', '')
        ]
        cfg = dec.build_cfg(insns)
        code = dec.decompile_cfg_to_c("fn_test", cfg)
        self.assertIn("fn_test", code)
        self.assertIn("result", code)
        # Verify unused registers are eliminated
        self.assertNotIn("RegValue counter", code)
        self.assertNotIn("RegValue flags", code)
        self.assertNotIn("RegValue r10", code)
        self.assertNotIn("local_stack_frame", code)

    def test_domain_clusterer(self):
        clusterer = DomainClusterer("dummy_out")
        dom1 = clusterer.classify_function("fn_foliage", 0x1000, "foliage brush limit", ["FoliageBrush"], "editor")
        self.assertEqual(dom1, "editor")

        dom2 = clusterer.classify_function("fn_storage", 0x2000, "storage code", ["settings.ini"], "storage")
        self.assertEqual(dom2, "storage")

        dom3 = clusterer.classify_function("fn_core", 0x3000, "boot manager", ["booted"], "core")
        self.assertEqual(dom3, "core")

if __name__ == '__main__':
    unittest.main()
