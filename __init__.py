from binaryninja import Architecture, Settings, BinaryViewType, BinaryView
from binaryninjaui import UIAction, UIActionHandler, Menu
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
)
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor, QFont
from PySide6.QtCore import QTimer

import re

settings = Settings()
settings.register_group("Shellcoder", "Shellcoder")


COMMENT_CHARS = ["#", ";", "//"]


class AssemblerWidget(QWidget):
    def __init__(self, parent=None):
        super(AssemblerWidget, self).__init__(parent)
        self.initUI()

    def initUI(self) -> None:
        layout = QVBoxLayout()

        # Architecture selection
        arch_layout = QHBoxLayout()
        arch_label = QLabel("Architecture:")
        self.arch_combo = QComboBox()
        for arch in list(Architecture):
            self.arch_combo.addItem(arch.name)
        arch_layout.addWidget(arch_label)
        arch_layout.addWidget(self.arch_combo)
        layout.addLayout(arch_layout)

        # Endianness selection
        # endian_layout = QHBoxLayout()
        # endian_label = QLabel("Endianness:")
        # self.endian_combo = QComboBox()
        # self.endian_combo.addItems(["Little Endian", "Big Endian"])
        # endian_layout.addWidget(endian_label)
        # endian_layout.addWidget(self.endian_combo)
        # layout.addLayout(endian_layout)

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
        self.byte_boundary_checkbox.setToolTip(
            "Enable this option to ensure the search pattern is only matched within the boundaries of a byte"
        )
        self.byte_boundary_checkbox.setChecked(True)  # Default to checked
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

        # Add checkbox for instruction-size-based search
        self.instruction_size_checkbox = QCheckBox("Respect instruction boundaries")
        self.instruction_size_checkbox.setToolTip(
            "Enable this option to ensure bad patterns are only searched wthin the boundaries of an instruction"
        )
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
        self.search_results = QLabel()
        self.search_results.setWordWrap(True)
        layout.addWidget(self.search_results)

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

        # New output window for matches and offsets
        match_layout = QVBoxLayout()
        match_label = QLabel("Search Results:")
        self.match_output = QTextEdit()
        self.match_output.setReadOnly(True)
        match_layout.addWidget(match_label)
        match_layout.addWidget(self.match_output)
        layout.addLayout(match_layout)

        # Info display (for search results and bad chars)
        self.info_display = QLabel()
        self.info_display.setWordWrap(True)
        layout.addWidget(self.info_display)

        self.format_combo.currentIndexChanged.connect(self.toggle_mnemonic_options)
        self.setLayout(layout)

    def update_output(self):
        # This method will be called when the output format is changed
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

    def toggle_mnemonic_options(self, index):
        if self.format_combo.itemText(index) == "Mnemonics":
            self.mnemonic_options.show()
            self.base_address_widget.show()
        else:
            self.mnemonic_options.hide()
            self.base_address_widget.hide()
        self.update_output()

    def copy_output(self):
        output_text = self.output.toPlainText()
        clipboard = QApplication.clipboard()
        clipboard.setText(output_text)

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

    def check_bad_patterns(self):
        bad_patterns_input = self.bad_chars_input.text().strip()
        assembled_text = self.output.toPlainText()
        respect_instructions = self.instruction_size_checkbox.isChecked()
        # TODO: Figure this out
        instruction_width = (
            4  # Default to 4 bytes, but this should be adjustable based on architecture
        )

        print(f"Debug: Bad patterns input: {bad_patterns_input}")
        print(f"Debug: Assembled text: {assembled_text}")
        print(f"Debug: Respect instruction boundaries: {respect_instructions}")
        print(f"Debug: Instruction width: {instruction_width} bytes")

        self.match_output.clear()  # Clear previous results

        try:
            bad_patterns = [
                bytes.fromhex(pattern.replace(" ", ""))
                for pattern in bad_patterns_input.split()
            ]
            print(
                f"Debug: Parsed bad patterns: {[pattern.hex() for pattern in bad_patterns]}"
            )
        except ValueError as e:
            print(f"Debug: Error parsing bad patterns: {str(e)}")
            self.match_output.append(
                "Invalid input. Use hex format (e.g., 00 0a 0d d287)"
            )
            self.info_display.setText("Invalid input.")
            return

        # Extract raw bytes
        if "\\x" in assembled_text:  # Inline format
            shellcode_bytes = bytes.fromhex(
                assembled_text.replace('"', "").replace("\\x", "")
            )
            print("Debug: Detected Inline format")
        elif "shellcode = [" in assembled_text:  # Python format
            hex_values = re.findall(r'b"([0-9a-fA-F]+)"', assembled_text)
            shellcode_bytes = b"".join(bytes.fromhex(value) for value in hex_values)
            print("Debug: Detected Python format")
        elif "0x" in assembled_text:  # C-Array format
            print("Debug: Detected C-Array format")
            array_content = re.search(r"\{(.*?)\}", assembled_text, re.DOTALL)
            if array_content:
                hex_values = re.findall(
                    r"0x([0-9a-fA-F]{2})(?:\s*,|\s*$)", array_content.group(1)
                )
                print(f"Debug: Extracted hex values: {hex_values}")
                shellcode_bytes = bytes.fromhex("".join(hex_values))
            else:
                print("Debug: Could not find array content")
                shellcode_bytes = b""
        else:  # Hex format
            shellcode_bytes = bytes.fromhex(re.sub(r"\s", "", assembled_text))
            print("Debug: Detected Hex format")

        print(f"Debug: Extracted shellcode bytes: {shellcode_bytes.hex()}")
        print(
            f"Debug: Extracted shellcode bytes (spaced): {' '.join([f'{b:02x}' for b in shellcode_bytes])}"
        )

        found_bad_patterns = []
        for pattern in bad_patterns:
            pattern_hex = pattern.hex()
            print(f"Debug: Searching for pattern: {pattern_hex}")
            for i in range(len(shellcode_bytes) - len(pattern) + 1):
                if respect_instructions:
                    instruction_start = (i // instruction_width) * instruction_width
                    if i + len(pattern) > instruction_start + instruction_width:
                        continue
                if shellcode_bytes[i : i + len(pattern)] == pattern:
                    found_bad_patterns.append((i, pattern))
                    print(f"Debug: Found pattern at offset {i}")

        if found_bad_patterns:
            self.match_output.append("Bad patterns found:")
            for offset, pattern in found_bad_patterns:
                self.match_output.append(f"Offset {offset}: {pattern.hex(' ')}")
            self.info_display.setText(
                f"Found {len(found_bad_patterns)} bad pattern(s)."
            )
        else:
            self.match_output.append("No bad patterns found.")
            self.info_display.setText("No bad patterns found.")

        print(f"Debug: Found bad patterns: {found_bad_patterns}")

        # Clear existing highlighting before checking for bad patterns
        self.clear_highlighting()

        # Highlight bad patterns in the output
        self.highlight_bad_patterns(assembled_text, found_bad_patterns)

    def highlight_bad_patterns(self, text, found_bad_patterns):
        cursor = self.output.textCursor()
        cursor.beginEditBlock()

        # Define highlight format
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 200, 200))  # Light red background
        highlight_format.setForeground(QColor(0, 0, 0))  # Black text

        print("Debug: Starting highlighting process")
        print(f"Text: {text}")

        # Highlight bad patterns
        for offset, pattern in found_bad_patterns:
            pattern_hex = pattern.hex()
            print(f"Debug: Highlighting pattern {pattern_hex} at offset {offset}")
            if "\\x" in text:  # Inline format
                start = text.index('"') + 1 + offset * 4
                length = len(pattern) * 4
                print(f"Debug: Inline format - start: {start}, length: {length}")
                self.highlight_range(cursor, start, length, highlight_format)
            elif "shellcode = [" in text:  # Python format
                cumulative_length = 0
                pattern_length = len(pattern)
                for match in re.finditer(r'b"([0-9a-fA-F]+)"', text):
                    chunk_length = len(match.group(1)) // 2
                    if cumulative_length <= offset < cumulative_length + chunk_length:
                        relative_offset = offset - cumulative_length
                        start = match.start() + 2 + relative_offset * 2
                        length = min(pattern_length, chunk_length - relative_offset) * 2
                        self.highlight_range(cursor, start, length, highlight_format)
                        pattern_length -= chunk_length - relative_offset
                        if pattern_length <= 0:
                            break
                    elif (
                        cumulative_length
                        < offset + len(pattern)
                        <= cumulative_length + chunk_length
                    ):
                        start = match.start() + 2
                        length = (offset + len(pattern) - cumulative_length) * 2
                        self.highlight_range(cursor, start, length, highlight_format)
                        break
                    cumulative_length += chunk_length
                print("Debug: Python format - highlighted pattern across chunks")
            elif "0x" in text:  # C-Array format
                # Find all '0x' occurrences but skip mnemonic '0x' in comments when `//` is encountered, then goto next line
                hex_positions = []
                for match in re.finditer(r"0x[0-9a-fA-F]{2}", text):
                    # Check if '0x' is within a comment
                    before = text[: match.start()]
                    if (
                        "//" in before.splitlines()[-1]
                    ):  # Check if '0x' is after '//' in the same line
                        continue
                    hex_positions.append(match.start())

                for i in range(len(pattern)):
                    if offset + i < len(hex_positions):
                        start = hex_positions[offset + i]
                        byte_match = re.match(r"0x([0-9a-fA-F]{2})", text[start:])
                        if byte_match:
                            byte_value = byte_match.group(1)
                            self.highlight_range(
                                cursor, start, 4, highlight_format
                            )  # Highlight '0xXX'
                            print(
                                f"Debug: C-Array format - highlighted byte 0x{byte_value} at position {start}"
                            )
                        else:
                            print(
                                f"Debug: C-Array format - unexpected format at position {start}"
                            )
                    else:
                        print(
                            f"Debug: C-Array format - byte at offset {offset + i} not found"
                        )
                print("Debug: C-Array format - highlighted pattern across bytes")
            else:  # Hex format
                start = offset * 3
                length = len(pattern) * 3 - 1
                print(f"Debug: Hex format - start: {start}, length: {length}")
                self.highlight_range(cursor, start, length, highlight_format)

        cursor.endEditBlock()
        self.output.setTextCursor(cursor)
        print("Debug: Finished highlighting process")

    def highlight_range(self, cursor, start, length, format):
        cursor.setPosition(start)
        cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, length)
        cursor.mergeCharFormat(format)

    def assemble(self) -> None:
        current_info = self.info_display.text()
        print("Assemble button clicked")  # Debug output
        arch_name = self.arch_combo.currentText()
        # endianness = self.endian_combo.currentText()
        output_format = self.format_combo.currentText()

        try:
            arch = Architecture[arch_name]
            # is_big_endian = endianness == "Big Endian"

            # if is_big_endian != (arch.endianness == Endianness.BigEndian):
            #     for potential_arch in Architecture:
            #         if (potential_arch.name.lower() == arch.name.lower() and
            #             potential_arch.endianness == (Endianness.BigEndian if is_big_endian else Endianness.LittleEndian)):
            #             arch = potential_arch
            #             break
            #     else:
            #         raise ValueError(f"No {endianness} version found for {arch_name}")

            input_text = self.asm_input.toPlainText()
            assembled_instructions = []
            total_bytes = 0

            # Determine input type
            non_comment_lines = [
                line.strip()
                for line in input_text.split("\n")
                if line.strip() and not line.strip().startswith(tuple(COMMENT_CHARS))
            ]
            if all(
                all(c in "0123456789ABCDEFabcdef \\x\"'" for c in line)
                for line in non_comment_lines
            ):
                # Hex or inline input
                processed_input = bytearray()
                for line in input_text.split("\n"):
                    line = line.strip()
                    if line.startswith(tuple(COMMENT_CHARS)):
                        continue  # Skip comment lines
                    if line:
                        if line.startswith('"') and line.endswith('"'):
                            # Inline format
                            processed_input.extend(
                                bytes.fromhex(line.strip('"').replace("\\x", ""))
                            )
                        else:
                            # Hex format
                            processed_input.extend(bytes.fromhex(line.replace(" ", "")))

                # Create a temporary BinaryView
                bv = BinaryView.new(data=processed_input)
                bv.arch = arch
                bv.platform = arch.standalone_platform

                # Disassemble
                offset = 0
                while offset < len(processed_input):
                    disassembly = bv.get_disassembly(offset)
                    if disassembly is None:
                        break
                    instruction_length = len(bv.read(offset, arch.max_instr_length))
                    assembled_instructions.append({
                        "type": "instruction",
                        "asm": disassembly,
                        "bytes": processed_input[offset : offset + instruction_length],
                    })
                    offset += instruction_length
                    total_bytes += instruction_length
            else:
                # Assembly input
                for line in input_text.split("\n"):
                    line = line.strip()
                    if line.startswith(tuple(COMMENT_CHARS)):
                        assembled_instructions.append({
                            "type": "comment",
                            "content": line,
                        })
                    elif line:
                        try:
                            result = arch.assemble(line)
                            assembled_instructions.append({
                                "type": "instruction",
                                "asm": line,
                                "bytes": result,
                            })
                            total_bytes += len(result)
                        except Exception as e:
                            raise ValueError(
                                f"Could not assemble line: '{line}'. Error: {str(e)}"
                            )

            if not assembled_instructions:
                raise ValueError("No instructions were assembled or disassembled")

            formatted_output = self.format_output(
                assembled_instructions, output_format, total_bytes
            )
            self.output.setPlainText(formatted_output)
            self.clear_highlighting()  # Clear any existing highlighting

            # Update length display
            self.length_value.setText(f"{total_bytes} bytes")

            print(f"Assembled: {formatted_output}")  # Debug output

        except Exception as e:
            error_message = f"Error: {str(e)}"
            self.output.setPlainText(error_message)
            print(error_message)  # Debug output
        finally:
            self.info_display.setText(current_info)

    def format_output(self, assembled_instructions, output_format, total_bytes):
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
                else:  # instruction
                    lines.append(f'    b"{instr["bytes"].hex()}",  # {instr["asm"]}')
            return (
                "shellcode = [\n"
                + "\n".join(lines)
                + f"\n]\n\n# Total length: {total_bytes} bytes\nshellcode_length = {total_bytes}\nraw_shellcode = b''.join(shellcode)"
            )

        elif output_format == "C-Array":
            lines = []
            for instr in assembled_instructions:
                if instr["type"] == "comment":
                    lines.append(
                        f"    {instr['content'].replace('#', '//').replace(';', '//')}"
                    )
                else:  # instruction
                    hex_bytes = [f"0x{b:02x}" for b in instr["bytes"]]
                    lines.append(f"    {', '.join(hex_bytes)},  // {instr['asm']}")
            return (
                "unsigned char shellcode[] = {\n"
                + "\n".join(lines)
                + f"\n}};\n\n// Total length: {total_bytes} bytes\nconst size_t shellcode_length = {total_bytes};"
            )

        elif output_format == "Mnemonics":
            lines = []
            base_address = int(self.base_address_input.text(), 16)
            address = base_address
            for instr in assembled_instructions:
                if instr["type"] == "comment":
                    lines.append(instr["content"])
                else:  # instruction
                    line_parts = []
                    if self.show_addresses.isChecked():
                        line_parts.append(f"{address:08x}:")
                    if self.show_bytecodes.isChecked():
                        line_parts.append(f"{instr['bytes'].hex():<16}")
                    if self.show_instructions.isChecked():
                        # Handle address-sensitive operations here
                        asm = instr["asm"]
                        if (
                            "j" in asm and "+" in asm
                        ):  # Simple check for jump instructions
                            parts = asm.split()
                            for i, part in enumerate(parts):
                                if part.startswith(".+"):
                                    try:
                                        offset = int(part[2:])
                                        parts[i] = f"0x{address + offset:x}"
                                    except ValueError:
                                        pass  # If we can't parse the offset, leave it as is
                            asm = " ".join(parts)
                        line_parts.append(asm)
                    lines.append("  ".join(line_parts))
                    address += len(instr["bytes"])
            return "\n".join(lines)

        else:
            return "Unsupported output format"

    def search_pattern(self):
        pattern = self.search_input.text()
        respect_boundaries = self.byte_boundary_checkbox.isChecked()
        assembled_text = self.output.toPlainText()

        self.match_output.clear()  # Clear previous results

        # Extract raw bytes regardless of format
        if "\\x" in assembled_text:  # Inline format
            raw_bytes = bytes.fromhex(
                assembled_text.replace('"', "").replace("\\x", "")
            )
        elif "shellcode = [" in assembled_text:  # Python format
            hex_values = re.findall(r'b"([0-9a-fA-F]+)"', assembled_text)
            raw_bytes = b"".join(bytes.fromhex(value) for value in hex_values)
        elif "0x" in assembled_text:  # C-Array format
            hex_values = re.findall(r"0x([0-9a-fA-F]{2}),", assembled_text)
            raw_bytes = bytes.fromhex("".join(hex_values))
        else:  # Hex format
            raw_bytes = bytes.fromhex(assembled_text.replace(" ", ""))

        if respect_boundaries:
            hex_string = " ".join(f"{b:02x}" for b in raw_bytes)
        else:
            hex_string = raw_bytes.hex()

        try:
            if respect_boundaries:
                # Modify the pattern to ensure it matches whole bytes
                byte_pattern = " ".join(
                    pattern[i : i + 2] for i in range(0, len(pattern), 2)
                )
                matches = list(re.finditer(byte_pattern, hex_string))
            else:
                matches = list(re.finditer(pattern, hex_string))

            if matches:
                for match in matches:
                    if respect_boundaries:
                        offset = match.start() // 3
                        matched_bytes = match.group().replace(" ", "")
                    else:
                        offset = match.start() // 2
                        matched_bytes = match.group()
                    self.match_output.append(f"Offset {offset}: {matched_bytes}")
            else:
                self.match_output.append("No matches found.")

            # Update the info display with a summary
            if matches:
                self.info_display.setText(f"Found {len(matches)} match(es).")
            else:
                self.info_display.setText("No matches found.")

        except re.error as e:
            self.match_output.append(f"Invalid regex pattern: {str(e)}")
            self.info_display.setText("Invalid regex pattern.")

    def disassemble_input(self, input_bytes, arch_name):
        try:
            arch = Architecture[arch_name]
            disassembly = []
            offset = 0
            while offset < len(input_bytes):
                inst = arch.disassemble(input_bytes[offset:], addr=offset)
                if inst is None:
                    break
                disassembly.append(f"{offset:04x}: {inst}")
                offset += inst.length
            return "\n".join(disassembly)
        except Exception as e:
            return f"Disassembly error: {str(e)}"


assembler_widget = None


def run_plugin(bv) -> None:
    global assembler_widget
    assembler_widget = AssemblerWidget()
    assembler_widget.show()


UIAction.registerAction("Shellcoder\\Assemble")
UIActionHandler.globalActions().bindAction("Shellcoder\\Run", UIAction(run_plugin))
Menu.mainMenu("Plugins").addAction("Shellcoder\\Run", "Shellcoder")
