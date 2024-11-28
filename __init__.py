from binaryninja import Architecture, BinaryView
from binaryninjaui import UIAction, UIActionHandler, Menu, UIContext
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QPushButton,
    QComboBox,
    QLabel,
    QLineEdit,
    QCheckBox,
    QMessageBox,
)
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor, QFont
from PySide6.QtCore import QTimer

import re
from typing import List, Dict

# Constants
COMMENT_CHARS = ["#", ";", "//"]


class AssemblerError(Exception):
    pass


class DisassemblerError(Exception):
    pass


class Assembler:
    def __init__(self) -> None:
        self.arch: Architecture = None

    def set_architecture(self, arch_name: str) -> None:
        try:
            self.arch = Architecture[arch_name]
        except KeyError:
            raise AssemblerError(f"Unsupported architecture: {arch_name}")

    def assemble(self, input_text: str) -> List[Dict]:
        assembled_instructions = []
        for line in input_text.split("\n"):
            line = line.strip()
            if line.startswith(tuple(COMMENT_CHARS)):
                assembled_instructions.append({"type": "comment", "content": line})
            elif line:
                try:
                    result = self.arch.assemble(line)
                    assembled_instructions.append(
                        {
                            "type": "instruction",
                            "asm": line,
                            "bytes": result,
                        }
                    )
                except Exception as e:
                    raise AssemblerError(
                        f"Could not assemble line: '{line}'. Error: {str(e)}"
                    )

        if not assembled_instructions:
            raise AssemblerError("No instructions were assembled")

        return assembled_instructions

    def disassemble(self, input_bytes: bytes) -> List[Dict]:
        disassembled_instructions = []
        bv = BinaryView.new(data=input_bytes)
        bv.arch = self.arch
        bv.platform = self.arch.standalone_platform

        offset = 0
        while offset < len(input_bytes):
            disassembly = bv.get_disassembly(offset)
            if disassembly is None:
                break
            instruction_length = len(bv.read(offset, self.arch.max_instr_length))
            disassembled_instructions.append(
                {
                    "type": "instruction",
                    "asm": disassembly,
                    "bytes": input_bytes[offset : offset + instruction_length],
                }
            )
            offset += instruction_length

        if not disassembled_instructions:
            raise DisassemblerError("No instructions were disassembled")

        return disassembled_instructions

    def format_output(
        self,
        assembled_instructions: List[Dict],
        output_format: str,
        total_bytes: int,
        mnemonic_options: Dict = {},
    ) -> str:
        if total_bytes == 0:
            return "No instructions to assemble"

        if output_format == "Inline":
            return (
                '"'
                + "".join(
                    f"\\x{b:02x}"
                    for instr in assembled_instructions
                    if instr["type"] == "instruction"
                    for b in instr["bytes"]
                )
                + '"'
            )

        elif output_format == "Hex":
            return " ".join(
                f"{b:02x}"
                for instr in assembled_instructions
                if instr["type"] == "instruction"
                for b in instr["bytes"]
            )

        elif output_format == "Python":
            lines = []
            for instr in assembled_instructions:
                if instr["type"] == "comment":
                    lines.append(
                        f"    {instr['content'].replace('//', '#').replace(';', '#')}"
                    )
                else:
                    lines.append(f'    b"{instr["bytes"].hex()}",  # {instr["asm"]}')
            return (
                "shellcode = [\n"
                + "\n".join(lines)
                + f"\n]\n\n# Total length: {total_bytes} bytes\n"
                f"shellcode_length = {total_bytes}\n"
                f"raw_shellcode = b''.join(shellcode)"
            )

        elif output_format == "C-Array":
            lines = []
            for instr in assembled_instructions:
                if instr["type"] == "comment":
                    lines.append(
                        f"    {instr['content'].replace('#', '//').replace(';', '//')}"
                    )
                else:
                    hex_bytes = [f"0x{b:02x}" for b in instr["bytes"]]
                    lines.append(f"    {', '.join(hex_bytes)},  // {instr['asm']}")
            return (
                "unsigned char shellcode[] = {{\n"
                + "\n".join(lines)
                + f"\n}};\n\n// Total length: {total_bytes} bytes\n"
                f"const size_t shellcode_length = {total_bytes};"
            )

        elif output_format == "Mnemonics":
            lines = []
            address = mnemonic_options.get("base_address", 0) if mnemonic_options else 0
            for instr in assembled_instructions:
                if instr["type"] == "comment":
                    lines.append(instr["content"])
                else:
                    line_parts = []
                    if mnemonic_options.get("show_addresses", True):
                        line_parts.append(f"{address:08x}:")
                    if mnemonic_options.get("show_bytecodes", True):
                        line_parts.append(f"{instr['bytes'].hex():<16}")
                    if mnemonic_options.get("show_instructions", True):
                        line_parts.append(instr["asm"])
                    lines.append("  ".join(line_parts))
                    address += len(instr["bytes"])
            return "\n".join(lines)

        else:
            raise AssemblerError(f"Unsupported output format: {output_format}")

    def search_pattern(
        self, assembled_bytes: bytes, pattern: str, respect_boundaries: bool
    ) -> List[Dict]:
        if respect_boundaries:
            hex_string = " ".join(f"{b:02x}" for b in assembled_bytes)
            byte_pattern = " ".join(
                pattern[i : i + 2] for i in range(0, len(pattern), 2)
            )
            matches = list(re.finditer(byte_pattern, hex_string))
            return [
                {
                    "offset": match.start() // 3,
                    "matched": match.group().replace(" ", ""),
                }
                for match in matches
            ]
        else:
            hex_string = assembled_bytes.hex()
            matches = list(re.finditer(pattern, hex_string))
            return [
                {"offset": match.start() // 2, "matched": match.group()}
                for match in matches
            ]

    def check_bad_patterns(
        self,
        assembled_bytes: bytes,
        bad_patterns: List[bytes],
        respect_instructions: bool,
    ) -> List[Dict]:
        found_bad_patterns = []
        instruction_width = 4  # Default to 4 bytes, adjust based on architecture

        for pattern in bad_patterns:
            for i in range(len(assembled_bytes) - len(pattern) + 1):
                if respect_instructions:
                    instruction_start = (i // instruction_width) * instruction_width
                    if i + len(pattern) > instruction_start + instruction_width:
                        continue
                if assembled_bytes[i : i + len(pattern)] == pattern:
                    found_bad_patterns.append({"offset": i, "pattern": pattern.hex()})

        return found_bad_patterns


class AssemblerWidget(QWidget):
    def __init__(self, parent=None):
        super(AssemblerWidget, self).__init__(parent)

        # To get a binaryview we can use the UIContext of the currently opened file/db
        view = UIContext.activeContext().getCurrentView()
        # Get the actual BinaryView from the UI view
        self.bv = view.getData() if view else None
        # Now we can access the architecture
        self._current_arch = self.bv.arch if self.bv else None
        self.assembler = Assembler()
        self.initUI()

    def initUI(self) -> None:
        layout = QVBoxLayout()

        # Architecture selection
        arch_layout = QHBoxLayout()
        arch_label = QLabel("Architecture:")
        self.arch_combo = QComboBox()
        for arch in list(Architecture):
            self.arch_combo.addItem(arch.name)
        if self._current_arch:
            self.arch_combo.setCurrentText(self._current_arch.name)
        arch_layout.addWidget(arch_label)
        arch_layout.addWidget(self.arch_combo)
        layout.addLayout(arch_layout)

        # Output format selection
        format_layout = QHBoxLayout()
        format_label = QLabel("Output Format:")
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Inline", "Hex", "Python", "C-Array", "Mnemonics"])
        self.format_combo.currentIndexChanged.connect(self.update_output)
        format_layout.addWidget(format_label)
        format_layout.addWidget(self.format_combo)
        layout.addLayout(format_layout)

        # Mnemonic format options (initially hidden)
        self.mnemonic_options = QWidget()
        mnemonic_layout = QHBoxLayout()
        self.show_addresses = QCheckBox("Addresses")
        self.show_addresses.setToolTip(
            "Enable this option to display the address of each instruction"
        )
        self.show_bytecodes = QCheckBox("Bytecodes")
        self.show_bytecodes.setToolTip(
            "Enable this option to display the raw bytes of each instruction"
        )
        self.show_bytecodes.setChecked(True)
        self.show_instructions = QCheckBox("Instructions")
        self.show_instructions.setToolTip(
            "Enable this option to display the mnemonic of each instruction"
        )
        self.show_instructions.setChecked(True)
        mnemonic_layout.addWidget(self.show_addresses)
        mnemonic_layout.addWidget(self.show_bytecodes)
        mnemonic_layout.addWidget(self.show_instructions)
        self.mnemonic_options.setLayout(mnemonic_layout)
        self.mnemonic_options.hide()
        layout.addWidget(self.mnemonic_options)

        # Base address input
        self.base_address_widget = QWidget()
        base_address_layout = QHBoxLayout()
        base_address_label = QLabel("Base Address:")
        self.base_address_input = QLineEdit()
        self.base_address_input.setText("0")
        base_address_layout.addWidget(base_address_label)
        base_address_layout.addWidget(self.base_address_input)
        self.base_address_widget.setLayout(base_address_layout)
        self.base_address_widget.hide()
        layout.addWidget(self.base_address_widget)

        # Assembly input
        self.asm_input = QTextEdit()
        input_label = QLabel("Input:")
        self.asm_input.setPlaceholderText(
            "Enter assembly instructions (one per line), or inline/hex formatted shellcode"
        )
        layout.addWidget(input_label)
        layout.addWidget(self.asm_input)

        # Assemble button
        self.assemble_button = QPushButton("Run")
        self.assemble_button.clicked.connect(self.assemble)
        layout.addWidget(self.assemble_button)

        # Output display
        self.output = QTextEdit()
        output_label = QLabel("Output:")
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Monospace"))
        layout.addWidget(output_label)
        layout.addWidget(self.output)

        # Copy button
        self.copy_button = QPushButton("Copy Output")
        self.copy_button.clicked.connect(self.copy_output)
        layout.addWidget(self.copy_button)

        # Search pattern
        search_layout = QHBoxLayout()
        search_label = QLabel("Search pattern:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Enter a regex pattern (e.g., 00.. or 00(?!FF))"
        )
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_pattern)
        self.byte_boundary_checkbox = QCheckBox("Respect byte boundaries")
        self.byte_boundary_checkbox.setChecked(True)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.search_button)
        search_layout.addWidget(self.byte_boundary_checkbox)
        layout.addLayout(search_layout)

        # Bad characters input
        bad_chars_layout = QHBoxLayout()
        bad_chars_label = QLabel("Bad patterns:")
        self.bad_chars_input = QLineEdit()
        self.bad_chars_input.setPlaceholderText(
            "Enter bad patterns (e.g., 00 0a 0d fffe)"
        )
        self.bad_chars_check = QPushButton("Check Bad Patterns")
        self.bad_chars_check.clicked.connect(self.check_bad_patterns)
        bad_chars_layout.addWidget(bad_chars_label)
        bad_chars_layout.addWidget(self.bad_chars_input)
        bad_chars_layout.addWidget(self.bad_chars_check)
        layout.addLayout(bad_chars_layout)

        # Instruction boundary checkbox for bad pattern search
        self.instruction_size_checkbox = QCheckBox("Respect instruction boundaries")
        layout.addWidget(self.instruction_size_checkbox)

        # Length display
        length_layout = QHBoxLayout()
        length_label = QLabel("Length:")
        self.length_value = QLabel("0 bytes")
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_value)
        length_layout.addStretch()
        layout.addLayout(length_layout)

        # Search results display
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        layout.addWidget(QLabel("Search Results:"))
        layout.addWidget(self.search_results)

        # Info display
        self.info_display = QLabel()
        self.info_display.setWordWrap(True)
        layout.addWidget(self.info_display)

        self.setLayout(layout)

        # Connect signals
        self.format_combo.currentIndexChanged.connect(self.toggle_mnemonic_options)
        self.show_addresses.stateChanged.connect(self.update_output)
        self.show_bytecodes.stateChanged.connect(self.update_output)
        self.show_instructions.stateChanged.connect(self.update_output)
        self.base_address_input.textChanged.connect(self.update_output)

    def toggle_mnemonic_options(self, index):
        if self.format_combo.itemText(index) == "Mnemonics":
            self.mnemonic_options.show()
            self.base_address_widget.show()
        else:
            self.mnemonic_options.hide()
            self.base_address_widget.hide()
        self.update_output()

    def update_output(self):
        self.assemble()
        self.clear_highlighting()

    def clear_highlighting(self):
        cursor = self.output.textCursor()
        cursor.beginEditBlock()
        cursor.select(QTextCursor.Document)
        cursor.setCharFormat(QTextCharFormat())
        cursor.clearSelection()
        cursor.endEditBlock()
        self.output.setTextCursor(cursor)

    def copy_output(self):
        output_text = self.output.toPlainText()
        QApplication.clipboard().setText(output_text)

        # Visual feedback
        original_text = self.copy_button.text()
        self.copy_button.setText("Copied!")
        self.copy_button.setEnabled(False)

        # Reset button after 1.5 seconds
        QTimer.singleShot(1500, lambda: self.reset_copy_button(original_text))

        self.info_display.setText("Output copied to clipboard")

    def reset_copy_button(self, original_text):
        self.copy_button.setText(original_text)
        self.copy_button.setEnabled(True)

    def assemble(self) -> None:
        current_info = self.info_display.text()
        arch_name = self.arch_combo.currentText()
        output_format = self.format_combo.currentText()

        try:
            self.assembler.set_architecture(arch_name)
            input_text = self.asm_input.toPlainText()

            # Determine if input is assembly or raw bytes
            if all(
                all(c in "0123456789ABCDEFabcdef \\x\"'" for c in line.strip())
                for line in input_text.split("\n")
                if line.strip() and not line.strip().startswith(tuple(COMMENT_CHARS))
            ):
                # Raw bytes input
                processed_input = bytearray()
                for line in input_text.split("\n"):
                    line = line.strip()
                    if line.startswith(tuple(COMMENT_CHARS)):
                        continue
                    if line:
                        if line.startswith('"') and line.endswith('"'):
                            processed_input.extend(
                                bytes.fromhex(line.strip('"').replace("\\x", ""))
                            )
                        else:
                            processed_input.extend(bytes.fromhex(line.replace(" ", "")))
                assembled_instructions = self.assembler.disassemble(processed_input)
            else:
                # Assembly input
                assembled_instructions = self.assembler.assemble(input_text)

            total_bytes = sum(
                len(instr["bytes"])
                for instr in assembled_instructions
                if instr["type"] == "instruction"
            )

            mnemonic_options = {
                "show_addresses": self.show_addresses.isChecked(),
                "show_bytecodes": self.show_bytecodes.isChecked(),
                "show_instructions": self.show_instructions.isChecked(),
                "base_address": int(self.base_address_input.text(), 16),
            }
            formatted_output = self.assembler.format_output(
                assembled_instructions, output_format, total_bytes, mnemonic_options
            )

            self.output.setPlainText(formatted_output)
            self.clear_highlighting()
            self.length_value.setText(f"{total_bytes} bytes")

        except (AssemblerError, DisassemblerError) as e:
            self.show_error(str(e))
        finally:
            self.info_display.setText(current_info)

    def search_pattern(self):
        pattern = self.search_input.text()
        respect_boundaries = self.byte_boundary_checkbox.isChecked()
        assembled_text = self.output.toPlainText()

        try:
            # Extract raw bytes
            assembled_bytes = self.get_raw_bytes(assembled_text)

            matches = self.assembler.search_pattern(
                assembled_bytes, pattern, respect_boundaries
            )

            self.search_results.clear()
            if matches:
                for match in matches:
                    self.search_results.append(
                        f"Offset {match['offset']}: {match['matched']}"
                    )
                self.info_display.setText(f"Found {len(matches)} match(es).")
            else:
                self.search_results.append("No matches found.")
                self.info_display.setText("No matches found.")

        except re.error as e:
            self.show_error(f"Invalid regex pattern: {str(e)}")

    def check_bad_patterns(self):
        bad_patterns_input = self.bad_chars_input.text().strip()
        assembled_text = self.output.toPlainText()
        respect_instructions = self.instruction_size_checkbox.isChecked()

        try:
            bad_patterns = [
                bytes.fromhex(pattern.replace(" ", ""))
                for pattern in bad_patterns_input.split()
            ]
            assembled_bytes = self.get_raw_bytes(assembled_text)

            found_bad_patterns = self.assembler.check_bad_patterns(
                assembled_bytes, bad_patterns, respect_instructions
            )

            self.search_results.clear()
            if found_bad_patterns:
                self.search_results.append("Bad patterns found:")
                for result in found_bad_patterns:
                    self.search_results.append(
                        f"Offset {result['offset']}: {result['pattern']}"
                    )
                self.info_display.setText(
                    f"Found {len(found_bad_patterns)} bad pattern(s)."
                )
            else:
                self.search_results.append("No bad patterns found.")
                self.info_display.setText("No bad patterns found.")

            # Highlight bad patterns in the output
            self.highlight_bad_patterns(assembled_text, found_bad_patterns)

        except ValueError as e:
            self.show_error(
                f"Invalid input. Use hex format (e.g., 00 0a 0d d287). Error: {str(e)}"
            )

    def get_raw_bytes(self, assembled_text: str) -> bytes:
        if "\\x" in assembled_text:  # Inline format
            return bytes.fromhex(assembled_text.replace('"', "").replace("\\x", ""))
        elif "shellcode = [" in assembled_text:  # Python format
            hex_values = re.findall(r'b"([0-9a-fA-F]+)"', assembled_text)
            return b"".join(bytes.fromhex(value) for value in hex_values)
        elif "0x" in assembled_text:  # C-Array format
            hex_values = re.findall(r"0x([0-9a-fA-F]{2})", assembled_text)
            return bytes.fromhex("".join(hex_values))
        else:  # Hex format
            return bytes.fromhex(re.sub(r"\s", "", assembled_text))

    def highlight_bad_patterns(
        self, assembled_text: str, found_bad_patterns: List[Dict]
    ):
        cursor = self.output.textCursor()
        cursor.beginEditBlock()

        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 200, 200))  # Light red background
        highlight_format.setForeground(QColor(0, 0, 0))  # Black text
        start = 0
        length = 0

        for result in found_bad_patterns:
            offset, pattern = result["offset"], result["pattern"]
            pattern_length = len(bytes.fromhex(pattern))

            if "\\x" in assembled_text:  # Inline format
                start = assembled_text.index('"') + 1 + offset * 4
                length = pattern_length * 4
            elif "shellcode = [" in assembled_text:  # Python format
                # Find the correct chunk and highlight within it
                cumulative_length = 0
                for match in re.finditer(r'b"([0-9a-fA-F]+)"', assembled_text):
                    chunk_length = len(match.group(1)) // 2
                    if cumulative_length <= offset < cumulative_length + chunk_length:
                        relative_offset = offset - cumulative_length
                        start = match.start() + 2 + relative_offset * 2
                        length = min(pattern_length, chunk_length - relative_offset) * 2
                        break
                    cumulative_length += chunk_length
            elif "0x" in assembled_text:  # C-Array format
                hex_positions = [
                    m.start() for m in re.finditer(r"0x[0-9a-fA-F]{2}", assembled_text)
                ]
                start = hex_positions[offset]
                length = pattern_length * 4
            else:  # Hex format
                start = offset * 3
                length = pattern_length * 3 - 1

            if not start:
                self.show_error("Could not find the start position for highlighting")
            if not length:
                self.show_error("Could not find the length for highlighting")
            cursor.setPosition(start)
            cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, length)
            cursor.mergeCharFormat(highlight_format)

        cursor.endEditBlock()
        self.output.setTextCursor(cursor)

    def show_error(self, message: str):
        QMessageBox.critical(self, "Error", message)
        self.search_results.setPlainText(f"Error: {message}")


assembler_widget = None


def run_plugin(bv) -> None:
    global assembler_widget
    assembler_widget = AssemblerWidget()
    assembler_widget.show()


UIAction.registerAction("Shellcoder\\Run")
UIActionHandler.globalActions().bindAction("Shellcoder\\Run", UIAction(run_plugin))
Menu.mainMenu("Plugins").addAction("Shellcoder\\Run", "Shellcoder")
