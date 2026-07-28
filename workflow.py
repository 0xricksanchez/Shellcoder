import re
from typing import Any, Dict, List, Optional, Tuple


def search_hex_pattern(
    hex_string: str, pattern: str, respect_boundaries: bool
) -> List[Dict]:
    matches = list(re.finditer(pattern, hex_string))
    if respect_boundaries:
        matches = [
            match
            for match in matches
            if match.start() % 2 == 0 and match.end() % 2 == 0
        ]
    return [
        {
            "offset": match.start() // 2,
            "matched": match.group(),
            "length": (match.end() - match.start() + (match.start() % 2) + 1)
            // 2,
        }
        for match in matches
        if match.end() > match.start()
    ]


def find_bad_patterns(
    assembled_bytes: bytes,
    bad_patterns: List[bytes],
    instruction_ranges: Optional[List[Tuple[int, int]]] = None,
) -> List[Dict]:
    found_bad_patterns = []

    for pattern in bad_patterns:
        for offset in range(len(assembled_bytes) - len(pattern) + 1):
            if assembled_bytes[offset : offset + len(pattern)] != pattern:
                continue
            if instruction_ranges is not None and not any(
                start <= offset and offset + len(pattern) <= end
                for start, end in instruction_ranges
            ):
                continue
            found_bad_patterns.append({"offset": offset, "pattern": pattern.hex()})

    return found_bad_patterns


class ShellcodeWorkflow:
    def __init__(self, assembler: Any, comment_chars: Tuple[str, ...]) -> None:
        self.assembler = assembler
        self.comment_chars = comment_chars

    def run(
        self,
        arch_name: str,
        input_text: str,
        input_mode: str,
        output_format: str,
        mnemonic_options: Dict,
    ) -> Tuple[Any, str]:
        self.assembler.set_architecture(arch_name)

        if input_mode == "Hex" or (
            input_mode == "Auto" and self._is_hex_input(input_text)
        ):
            result = self.assembler.disassemble(self._parse_hex(input_text))
        elif input_mode in ("Auto", "Assembly"):
            result = self.assembler.assemble(
                input_text, mnemonic_options.get("base_address", 0)
            )
        else:
            raise ValueError(f"Unsupported input mode: {input_mode}")

        return result, self.assembler.format_output(
            result, output_format, mnemonic_options
        )

    def _is_hex_input(self, input_text: str) -> bool:
        return all(
            all(char in "0123456789ABCDEFabcdef \\x\"'" for char in line.strip())
            for line in input_text.split("\n")
            if line.strip() and not line.strip().startswith(self.comment_chars)
        )

    def _parse_hex(self, input_text: str) -> bytes:
        raw_bytes = bytearray()
        for line in input_text.split("\n"):
            line = line.strip()
            if line.startswith(self.comment_chars):
                continue
            if line.startswith('"') and line.endswith('"'):
                raw_bytes.extend(bytes.fromhex(line.strip('"').replace("\\x", "")))
            elif line:
                raw_bytes.extend(bytes.fromhex(line.replace(" ", "")))
        return bytes(raw_bytes)
