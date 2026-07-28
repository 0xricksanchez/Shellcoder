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
    QTabWidget,
    QToolButton,
    QSplitter,
)
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor, QFontDatabase
from PySide6.QtCore import QTimer, Qt

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .workflow import ShellcodeWorkflow, find_bad_patterns, search_hex_pattern

# Constants
COMMENT_CHARS = ["#", ";", "//"]
BAD_PATTERN_PRESETS = {
    "C string": "00",
    "Line breaks": "0a 0d",
    "Whitespace": "09 0a 0d 20",
}


class AssemblerError(Exception):
    pass


class DisassemblerError(Exception):
    pass


@dataclass
class ShellcodeResult:
    instructions: List[Dict]
    source_lines: List[Optional[int]] = field(default_factory=list)

    @property
    def raw_bytes(self) -> bytes:
        return b"".join(
            instruction["bytes"]
            for instruction in self.instructions
            if instruction["type"] == "instruction"
        )

    @property
    def total_bytes(self) -> int:
        return len(self.raw_bytes)

    def source_line_at_offset(self, offset: int) -> Optional[int]:
        current_offset = 0
        for index, instruction in enumerate(self.instructions):
            if instruction["type"] != "instruction":
                continue
            instruction_end = current_offset + len(instruction["bytes"])
            if current_offset <= offset < instruction_end:
                if index < len(self.source_lines):
                    return self.source_lines[index]
                return None
            current_offset = instruction_end
        return None

    def byte_range_for_source_line(self, source_line: int) -> Optional[tuple]:
        current_offset = 0
        for index, instruction in enumerate(self.instructions):
            if instruction["type"] != "instruction":
                continue
            instruction_length = len(instruction["bytes"])
            if (
                index < len(self.source_lines)
                and self.source_lines[index] == source_line
            ):
                return current_offset, instruction_length
            current_offset += instruction_length
        return None


class Assembler:
    def __init__(self) -> None:
        self.arch: Architecture = None

    def set_architecture(self, arch_name: str) -> None:
        try:
            self.arch = Architecture[arch_name]
        except KeyError:
            raise AssemblerError(f"Unsupported architecture: {arch_name}")

    def assemble(self, input_text: str, address: int = 0) -> ShellcodeResult:
        comments = []
        source_lines = []
        for line_number, line in enumerate(input_text.split("\n"), start=1):
            line = line.strip()
            if line.startswith(tuple(COMMENT_CHARS)):
                comments.append({"type": "comment", "content": line})
            elif line:
                source_lines.append((line_number, line))

        if not source_lines:
            raise AssemblerError("No instructions were assembled")

        assembled_bytes = bytearray()
        source_ranges = []
        for index, (line_number, line) in enumerate(source_lines):
            try:
                if self.arch.name in ("mipsel32", "mips32"):
                    instruction_bytes = self.arch.assemble(
                        line, address + len(assembled_bytes)
                    )
                else:
                    instruction_bytes = self.arch.assemble(line)
            except Exception as e:
                message = e.args[0] if e.args else str(e)
                if isinstance(message, bytes):
                    message = message.decode(errors="replace")
                message = str(message).replace("\\n", "\n")
                if message.startswith("Could not assemble: b'") and message.endswith("'"):
                    message = message[len("Could not assemble: b'") : -1]
                raise AssemblerError(f"Line {line_number} ({line}):\n{message}")

            if (
                self.arch.name in ("mipsel32", "mips32")
                and index + 1 < len(source_lines)
                and len(instruction_bytes) > 4
                and instruction_bytes[-4:] == b"\x00\x00\x00\x00"
            ):
                instruction_bytes = instruction_bytes[:-4]

            start = len(assembled_bytes)
            assembled_bytes.extend(instruction_bytes)
            source_ranges.append((start, len(assembled_bytes), line_number))

        result = self.disassemble(bytes(assembled_bytes))
        instruction_source_lines = []
        offset = 0
        for instruction in result.instructions:
            source_line = next(
                (
                    line_number
                    for start, end, line_number in source_ranges
                    if start <= offset < end
                ),
                None,
            )
            instruction_source_lines.append(source_line)
            offset += len(instruction["bytes"])
        return ShellcodeResult(
            comments + result.instructions,
            [None] * len(comments) + instruction_source_lines,
        )

    def disassemble(self, input_bytes: bytes) -> ShellcodeResult:
        disassembled_instructions = []
        bv = BinaryView.new(data=input_bytes)
        bv.arch = self.arch
        bv.platform = self.arch.standalone_platform

        offset = 0
        while offset < len(input_bytes):
            disassembly = bv.get_disassembly(offset)
            if disassembly is None:
                break
            instruction_length = bv.get_instruction_length(offset)
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

        return ShellcodeResult(disassembled_instructions)

    def format_output(
        self,
        result: ShellcodeResult,
        output_format: str,
        mnemonic_options: Dict = None,
    ) -> str:
        assembled_instructions = result.instructions
        total_bytes = result.total_bytes
        mnemonic_options = mnemonic_options or {}
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
            bytecode_width = max(
                (
                    len(instruction["bytes"].hex())
                    for instruction in assembled_instructions
                    if instruction["type"] == "instruction"
                ),
                default=0,
            )
            for instr in assembled_instructions:
                if instr["type"] == "comment":
                    lines.append(instr["content"])
                else:
                    line_parts = []
                    if mnemonic_options.get("show_addresses", True):
                        line_parts.append(f"{address:08x}:")
                    if mnemonic_options.get("show_bytecodes", True):
                        line_parts.append(
                            f"{instr['bytes'].hex():<{bytecode_width}}"
                        )
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
        return search_hex_pattern(
            assembled_bytes.hex(), pattern, respect_boundaries
        )

    def check_bad_patterns(
        self,
        result: ShellcodeResult,
        bad_patterns: List[bytes],
        respect_instructions: bool,
    ) -> List[Dict]:
        instruction_ranges = None
        if respect_instructions:
            instruction_ranges = []
            offset = 0
            for instruction in result.instructions:
                if instruction["type"] != "instruction":
                    continue
                end = offset + len(instruction["bytes"])
                instruction_ranges.append((offset, end))
                offset = end

        return find_bad_patterns(result.raw_bytes, bad_patterns, instruction_ranges)


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
        self.workflow = ShellcodeWorkflow(self.assembler, tuple(COMMENT_CHARS))
        self.result = None
        self._syncing_selection = False
        self.bad_byte_ranges = []
        self.search_byte_ranges = []
        self.selected_byte_ranges = []
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

        input_mode_layout = QHBoxLayout()
        input_mode_label = QLabel("Input Mode:")
        self.input_mode_combo = QComboBox()
        self.input_mode_combo.addItems(["Auto", "Assembly", "Hex"])
        self.input_mode_combo.setToolTip(
            "Auto detects hex input. Select Assembly or Hex to override detection."
        )
        input_mode_layout.addWidget(input_mode_label)
        input_mode_layout.addWidget(self.input_mode_combo)
        layout.addLayout(input_mode_layout)

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
        self.base_address_input.setToolTip(
            "Address used for assembly and mnemonic display"
        )
        base_address_layout.addWidget(base_address_label)
        base_address_layout.addWidget(self.base_address_input)
        self.base_address_widget.setLayout(base_address_layout)
        layout.addWidget(self.base_address_widget)

        self.editor_splitter = QSplitter(Qt.Vertical)
        self.editor_splitter.setChildrenCollapsible(False)

        input_panel = QWidget()
        input_layout = QVBoxLayout(input_panel)
        self.asm_input = QTextEdit()
        input_label = QLabel("Input:")
        self.asm_input.setPlaceholderText(
            "Enter assembly instructions (one per line), or inline/hex formatted shellcode"
        )
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.asm_input)

        self.assemble_button = QPushButton("Run")
        self.assemble_button.clicked.connect(self.assemble)
        input_layout.addWidget(self.assemble_button)
        input_panel.setMinimumHeight(160)
        self.editor_splitter.addWidget(input_panel)

        output_panel = QWidget()
        output_layout = QVBoxLayout(output_panel)
        self.output = QTextEdit()
        output_label = QLabel("Output:")
        self.output.setReadOnly(True)
        self.output.setFont(
            QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        )
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output)

        copy_layout = QHBoxLayout()
        self.copy_button = QPushButton("Copy Output")
        self.copy_button.clicked.connect(self.copy_output)
        copy_layout.addWidget(self.copy_button)
        for label, output_format in (
            ("Copy Hex", "Hex"),
            ("Copy Inline", "Inline"),
            ("Copy Python", "Python"),
            ("Copy C", "C-Array"),
        ):
            button = QPushButton(label)
            button.clicked.connect(
                lambda _, format_name=output_format: self.copy_format(format_name)
            )
            copy_layout.addWidget(button)
        output_layout.addLayout(copy_layout)

        highlight_legend = QHBoxLayout()
        highlight_legend.addWidget(QLabel("Highlights:"))
        for label, color in (
            ("Bad pattern", "#b91c1c"),
            ("Search", "#0f766e"),
            ("Source selection", "#1e40af"),
        ):
            legend_item = QLabel(label)
            legend_item.setStyleSheet(
                f"background-color: {color}; color: white; padding: 2px 6px;"
            )
            highlight_legend.addWidget(legend_item)
        highlight_legend.addStretch()
        output_layout.addLayout(highlight_legend)
        output_panel.setMinimumHeight(160)
        self.editor_splitter.addWidget(output_panel)
        self.editor_splitter.setStretchFactor(0, 1)
        self.editor_splitter.setStretchFactor(1, 1)
        layout.addWidget(self.editor_splitter, 1)

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
        self.bad_pattern_preset = QComboBox()
        self.bad_pattern_preset.addItem("Preset")
        for label, value in BAD_PATTERN_PRESETS.items():
            self.bad_pattern_preset.addItem(label, value)
        self.bad_chars_input = QLineEdit()
        self.bad_chars_input.setPlaceholderText(
            "Enter bad patterns (e.g., 00 0a 0d fffe)"
        )
        self.bad_chars_check = QPushButton("Check Bad Patterns")
        self.bad_chars_check.clicked.connect(self.check_bad_patterns)
        bad_chars_layout.addWidget(bad_chars_label)
        bad_chars_layout.addWidget(self.bad_pattern_preset)
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

        inspection_header = QHBoxLayout()
        self.inspection_toggle = QToolButton()
        self.inspection_toggle.setText("Inspection")
        self.inspection_toggle.setCheckable(True)
        self.inspection_toggle.setChecked(True)
        self.inspection_toggle.setArrowType(Qt.DownArrow)
        self.inspection_toggle.toggled.connect(self.toggle_inspection)
        inspection_header.addWidget(self.inspection_toggle)
        inspection_header.addStretch()
        self.clear_highlights_button = QPushButton("Clear Highlights")
        self.clear_highlights_button.clicked.connect(self.clear_inspection)
        inspection_header.addWidget(self.clear_highlights_button)
        layout.addLayout(inspection_header)

        self.inspection_tabs = QTabWidget()
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        self.bad_pattern_results = QTextEdit()
        self.bad_pattern_results.setReadOnly(True)
        self.inspection_tabs.addTab(self.search_results, "Search")
        self.inspection_tabs.addTab(self.bad_pattern_results, "Bad Patterns")
        self.inspection_tabs.setMaximumHeight(180)
        layout.addWidget(self.inspection_tabs)

        # Info display
        self.info_display = QLabel()
        self.info_display.setWordWrap(True)
        self.info_display.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.info_display)

        self.copy_error_button = QPushButton("Copy Error")
        self.copy_error_button.clicked.connect(self.copy_error)
        self.copy_error_button.hide()
        layout.addWidget(self.copy_error_button)

        self.setLayout(layout)

        # Connect signals
        self.format_combo.currentIndexChanged.connect(self.toggle_mnemonic_options)
        self.show_addresses.stateChanged.connect(self.update_output)
        self.show_bytecodes.stateChanged.connect(self.update_output)
        self.show_instructions.stateChanged.connect(self.update_output)
        self.base_address_input.textChanged.connect(self.update_output)
        self.bad_pattern_preset.currentIndexChanged.connect(self.apply_bad_pattern_preset)
        self.asm_input.cursorPositionChanged.connect(self.highlight_source_output)
        self.output.cursorPositionChanged.connect(self.select_source_for_output)

    def toggle_mnemonic_options(self, index):
        if self.format_combo.itemText(index) == "Mnemonics":
            self.mnemonic_options.show()
        else:
            self.mnemonic_options.hide()
        self.update_output()

    def update_output(self):
        self.assemble()
        self.clear_highlighting()

    def clear_highlighting(self):
        self.bad_byte_ranges = []
        self.search_byte_ranges = []
        self.selected_byte_ranges = []
        self.refresh_highlighting()

    def clear_inspection(self):
        self.clear_highlighting()
        self.search_results.clear()
        self.bad_pattern_results.clear()
        self.info_display.setText("")

    def toggle_inspection(self, visible: bool):
        self.inspection_toggle.setArrowType(
            Qt.DownArrow if visible else Qt.RightArrow
        )
        self.clear_highlights_button.setVisible(visible)
        self.inspection_tabs.setVisible(visible)

    def copy_output(self):
        output_text = self.output.textCursor().selectedText()
        if not output_text:
            output_text = self.output.toPlainText()
        output_text = output_text.replace("\u2029", "\n")
        QApplication.clipboard().setText(output_text)

        # Visual feedback
        original_text = self.copy_button.text()
        self.copy_button.setText("Copied!")
        self.copy_button.setEnabled(False)

        # Reset button after 1.5 seconds
        QTimer.singleShot(1500, lambda: self.reset_copy_button(original_text))

        self.info_display.setText("Output copied to clipboard")

    def copy_format(self, output_format: str):
        if self.result is None:
            self.show_inline_error("Run a successful assembly or disassembly first")
            return

        QApplication.clipboard().setText(
            self.assembler.format_output(
                self.result, output_format, self.mnemonic_options_values()
            )
        )
        self.info_display.setText(f"{output_format} output copied to clipboard")

    def reset_copy_button(self, original_text):
        self.copy_button.setText(original_text)
        self.copy_button.setEnabled(True)

    def mnemonic_options_values(self) -> Dict:
        return {
            "show_addresses": self.show_addresses.isChecked(),
            "show_bytecodes": self.show_bytecodes.isChecked(),
            "show_instructions": self.show_instructions.isChecked(),
            "base_address": int(self.base_address_input.text(), 16),
        }

    def assemble(self) -> None:
        arch_name = self.arch_combo.currentText()
        input_mode = self.input_mode_combo.currentText()
        output_format = self.format_combo.currentText()
        self.result = None

        try:
            input_text = self.asm_input.toPlainText()

            mnemonic_options = self.mnemonic_options_values()
            result, formatted_output = self.workflow.run(
                arch_name, input_text, input_mode, output_format, mnemonic_options
            )

            self.result = result
            self.output.setPlainText(formatted_output)
            self.clear_highlighting()
            self.length_value.setText(f"{result.total_bytes} bytes")
            self.info_display.setStyleSheet("")
            self.copy_error_button.hide()
            if self.bad_chars_input.text().strip():
                self.check_bad_patterns()
            else:
                self.info_display.setText("")

        except (AssemblerError, DisassemblerError, ValueError) as e:
            self.show_inline_error(str(e))

    def search_pattern(self):
        pattern = self.search_input.text()
        respect_boundaries = self.byte_boundary_checkbox.isChecked()

        if self.result is None:
            self.show_error("Run a successful assembly or disassembly first")
            return

        try:
            matches = self.assembler.search_pattern(
                self.result.raw_bytes, pattern, respect_boundaries
            )
            self.search_byte_ranges = [
                (match["offset"], match["length"]) for match in matches
            ]
            self.refresh_highlighting()

            self.search_results.clear()
            self.inspection_toggle.setChecked(True)
            self.inspection_tabs.setCurrentWidget(self.search_results)
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
        respect_instructions = self.instruction_size_checkbox.isChecked()

        if self.result is None:
            self.show_error("Run a successful assembly or disassembly first")
            return

        try:
            bad_patterns = [
                bytes.fromhex(pattern.replace(" ", ""))
                for pattern in bad_patterns_input.split()
            ]
            found_bad_patterns = self.assembler.check_bad_patterns(
                self.result, bad_patterns, respect_instructions
            )

            self.bad_pattern_results.clear()
            self.inspection_toggle.setChecked(True)
            self.inspection_tabs.setCurrentWidget(self.bad_pattern_results)
            if found_bad_patterns:
                self.bad_pattern_results.append("Bad patterns found:")
                for result in found_bad_patterns:
                    self.bad_pattern_results.append(
                        f"Offset {result['offset']}: {result['pattern']}"
                    )
                self.info_display.setText(
                    f"Found {len(found_bad_patterns)} bad pattern(s)."
                )
            else:
                self.bad_pattern_results.append("No bad patterns found.")
                self.info_display.setText("No bad patterns found.")

            self.bad_byte_ranges = [
                (result["offset"], len(bytes.fromhex(result["pattern"])))
                for result in found_bad_patterns
            ]
            self.refresh_highlighting()

        except ValueError as e:
            self.show_error(
                f"Invalid input. Use hex format (e.g., 00 0a 0d d287). Error: {str(e)}"
            )

    def apply_bad_pattern_preset(self, index: int):
        pattern = self.bad_pattern_preset.itemData(index)
        if pattern is None:
            return
        self.bad_chars_input.setText(pattern)
        if self.result is not None:
            self.check_bad_patterns()

    def output_byte_positions(self) -> List[tuple]:
        output_text = self.output.toPlainText()
        output_format = self.format_combo.currentText()

        if output_format == "Inline":
            return [(match.start(), 4) for match in re.finditer(r"\\x[0-9a-fA-F]{2}", output_text)]
        if output_format == "Python":
            return [
                (match.start(1) + index, 2)
                for match in re.finditer(r'b"([0-9a-fA-F]+)"', output_text)
                for index in range(0, len(match.group(1)), 2)
            ]
        if output_format == "C-Array":
            return [(match.start(), 4) for match in re.finditer(r"0x[0-9a-fA-F]{2}", output_text)]
        if output_format == "Hex":
            return [(match.start(), 2) for match in re.finditer(r"[0-9a-fA-F]{2}", output_text)]
        if not self.show_bytecodes.isChecked() or self.result is None:
            return []

        positions = []
        search_start = 0
        for instruction in self.result.instructions:
            if instruction["type"] != "instruction":
                continue
            bytecode = instruction["bytes"].hex()
            start = output_text.find(bytecode, search_start)
            if start < 0:
                return []
            positions.extend((start + index, 2) for index in range(0, len(bytecode), 2))
            search_start = start + len(bytecode)
        return positions

    def refresh_highlighting(self):
        positions = self.output_byte_positions()
        if not positions:
            self.output.setExtraSelections([])
            return

        selections = []
        for ranges, color in (
            (self.bad_byte_ranges, QColor(185, 28, 28)),
            (self.search_byte_ranges, QColor(15, 118, 110)),
            (self.selected_byte_ranges, QColor(30, 64, 175)),
        ):
            for offset, length in ranges:
                for start, width in positions[offset : offset + length]:
                    cursor = self.output.textCursor()
                    cursor.setPosition(start)
                    cursor.movePosition(
                        QTextCursor.Right, QTextCursor.KeepAnchor, width
                    )
                    selection = QTextEdit.ExtraSelection()
                    selection.cursor = cursor
                    selection.format.setBackground(color)
                    selection.format.setForeground(QColor(255, 255, 255))
                    selections.append(selection)
        self.output.setExtraSelections(selections)

    def highlight_source_output(self):
        if self._syncing_selection or self.result is None:
            return

        cursor = self.asm_input.textCursor()
        start_line = self.asm_input.document().findBlock(
            cursor.selectionStart()
        ).blockNumber() + 1
        selection_end = cursor.selectionEnd()
        if selection_end > cursor.selectionStart():
            selection_end -= 1
        end_line = self.asm_input.document().findBlock(selection_end).blockNumber() + 1
        self.selected_byte_ranges = [
            byte_range
            for source_line in range(start_line, end_line + 1)
            if (byte_range := self.result.byte_range_for_source_line(source_line))
            is not None
        ]
        self.refresh_highlighting()

    def select_source_for_output(self):
        if self._syncing_selection or self.result is None:
            return

        output_position = self.output.textCursor().position()
        for offset, (start, length) in enumerate(self.output_byte_positions()):
            if start <= output_position < start + length:
                source_line = self.result.source_line_at_offset(offset)
                if source_line is None:
                    return
                self._syncing_selection = True
                cursor = QTextCursor(
                    self.asm_input.document().findBlockByNumber(source_line - 1)
                )
                cursor.movePosition(QTextCursor.StartOfBlock)
                cursor.movePosition(
                    QTextCursor.EndOfBlock, QTextCursor.KeepAnchor
                )
                self.asm_input.setTextCursor(cursor)
                self.asm_input.ensureCursorVisible()
                self._syncing_selection = False
                self.selected_byte_ranges = [
                    self.result.byte_range_for_source_line(source_line)
                ]
                self.refresh_highlighting()
                return

    def show_error(self, message: str):
        QMessageBox.critical(self, "Error", message)
        self.search_results.setPlainText(f"Error: {message}")

    def show_inline_error(self, message: str):
        self.info_display.setStyleSheet("color: #b00020;")
        self.info_display.setText(message)
        self.copy_error_button.show()

    def copy_error(self):
        QApplication.clipboard().setText(self.info_display.text())
        self.copy_error_button.setText("Copied")
        QTimer.singleShot(1500, lambda: self.copy_error_button.setText("Copy Error"))


assembler_widget = None


def run_plugin(bv) -> None:
    global assembler_widget
    assembler_widget = AssemblerWidget()
    assembler_widget.show()


UIAction.registerAction("Shellcoder\\Run")
UIActionHandler.globalActions().bindAction("Shellcoder\\Run", UIAction(run_plugin))
Menu.mainMenu("Plugins").addAction("Shellcoder\\Run", "Shellcoder")
