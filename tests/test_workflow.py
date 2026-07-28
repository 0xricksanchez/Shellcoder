import unittest

from workflow import ShellcodeWorkflow, find_bad_patterns, search_hex_pattern


class FakeAssembler:
    def set_architecture(self, arch_name):
        self.arch_name = arch_name

    def assemble(self, input_text, address=0):
        self.input_text = input_text
        self.address = address
        return ("assembly", input_text)

    def disassemble(self, input_bytes):
        self.input_bytes = input_bytes
        return ("bytes", input_bytes)

    def format_output(self, result, output_format, mnemonic_options):
        return f"{result}:{output_format}:{mnemonic_options['base_address']}"


class ShellcodeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.assembler = FakeAssembler()
        self.workflow = ShellcodeWorkflow(self.assembler, ("#", ";", "//"))
        self.options = {"base_address": 0}

    def test_runs_assembly_input(self):
        result, output = self.workflow.run(
            "x86", "nop", "Auto", "Hex", self.options
        )

        self.assertEqual(self.assembler.arch_name, "x86")
        self.assertEqual(result, ("assembly", "nop"))
        self.assertEqual(output, "('assembly', 'nop'):Hex:0")

    def test_uses_base_address_for_assembly(self):
        options = {"base_address": 0x401000}

        self.workflow.run("x86", "nop", "Assembly", "Hex", options)

        self.assertEqual(self.assembler.address, 0x401000)

    def test_forces_assembly_mode(self):
        result, _ = self.workflow.run(
            "x86", "90", "Assembly", "Hex", self.options
        )

        self.assertEqual(result, ("assembly", "90"))

    def test_runs_spaced_hex_input(self):
        result, _ = self.workflow.run(
            "x86", "90 90", "Auto", "Mnemonics", self.options
        )

        self.assertEqual(result, ("bytes", b"\x90\x90"))

    def test_runs_inline_hex_input(self):
        result, _ = self.workflow.run(
            "x86", r'"\x90\x90"', "Auto", "Mnemonics", self.options
        )

        self.assertEqual(result, ("bytes", b"\x90\x90"))

    def test_skips_comments_in_hex_input(self):
        result, _ = self.workflow.run(
            "x86", "# first\n90\n// last", "Auto", "Mnemonics", self.options
        )

        self.assertEqual(result, ("bytes", b"\x90"))

    def test_rejects_invalid_hex(self):
        with self.assertRaises(ValueError):
            self.workflow.run("x86", "9", "Hex", "Mnemonics", self.options)

    def test_search_respects_byte_boundaries(self):
        matches = search_hex_pattern("a00f", "00", True)

        self.assertEqual(matches, [])

    def test_search_preserves_regex_lookaheads(self):
        matches = search_hex_pattern("00ff0001", r"00(?!ff)", True)

        self.assertEqual(
            matches, [{"offset": 2, "matched": "00", "length": 1}]
        )

    def test_bad_patterns_can_cross_instruction_boundaries_when_disabled(self):
        matches = find_bad_patterns(
            bytes.fromhex("90c3"), [bytes.fromhex("90c3")]
        )

        self.assertEqual(matches, [{"offset": 0, "pattern": "90c3"}])

    def test_bad_patterns_do_not_cross_instruction_boundaries(self):
        matches = find_bad_patterns(
            bytes.fromhex("90c3"), [bytes.fromhex("90c3")], [(0, 1), (1, 2)]
        )

        self.assertEqual(matches, [])

    def test_bad_patterns_match_within_an_instruction_boundary(self):
        matches = find_bad_patterns(
            bytes.fromhex("4889e5"), [bytes.fromhex("89e5")], [(0, 3)]
        )

        self.assertEqual(matches, [{"offset": 1, "pattern": "89e5"}])


if __name__ == "__main__":
    unittest.main()
