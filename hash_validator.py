#!/usr/bin/env python3
"""Validate a file against an expected MD5 or SHA-256 checksum.

MD5 is provided for compatibility with legacy checksums. Prefer SHA-256 for
integrity validation whenever it is available.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import platform
import subprocess
import sys
from pathlib import Path


ALGORITHMS = {
    "md5": {"constructor": hashlib.md5, "digest_length": 32, "label": "MD5"},
    "sha256": {
        "constructor": hashlib.sha256,
        "digest_length": 64,
        "label": "SHA-256",
    },
}
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


class ValidationError(ValueError):
    """Raised when a requested validation cannot be performed safely."""


def normalize_expected_hash(expected_hash: str, algorithm: str) -> str:
    """Validate and normalize a hexadecimal checksum for *algorithm*."""
    expected = expected_hash.strip().lower()
    config = ALGORITHMS[algorithm]

    if len(expected) != config["digest_length"]:
        raise ValidationError(
            f"{config['label']} hashes must contain exactly "
            f"{config['digest_length']} hexadecimal characters."
        )
    if any(character not in "0123456789abcdef" for character in expected):
        raise ValidationError("Expected hash must contain only hexadecimal characters.")
    return expected


def calculate_hash(file_path: Path, algorithm: str, chunk_size: int) -> str:
    """Return a file digest while reading fixed-size chunks, not all at once."""
    digest = ALGORITHMS[algorithm]["constructor"]()
    with file_path.open("rb") as source_file:
        while chunk := source_file.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def validate_file(
    file_path: Path, expected_hash: str, algorithm: str, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> tuple[bool, str, int]:
    """Calculate and compare a file digest, returning validity, digest, and size."""
    if algorithm not in ALGORITHMS:
        raise ValidationError(f"Unsupported algorithm: {algorithm}")
    if chunk_size <= 0:
        raise ValidationError("Chunk size must be a positive integer.")
    if not file_path.exists():
        raise ValidationError(f"File does not exist: {file_path}")
    if not file_path.is_file():
        raise ValidationError(f"Path is not a regular file: {file_path}")

    normalized_expected = normalize_expected_hash(expected_hash, algorithm)
    calculated_hash = calculate_hash(file_path, algorithm, chunk_size)
    # compare_digest avoids leaking where two same-length digests differ.
    is_valid = hmac.compare_digest(calculated_hash, normalized_expected)
    return is_valid, calculated_hash, os.path.getsize(file_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a file against an expected MD5 or SHA-256 hash.",
        epilog="MD5 is legacy; prefer SHA-256 for integrity validation.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Use command-line arguments instead of prompts",
    )
    parser.add_argument(
        "--console",
        action="store_true",
        help="Use terminal prompts instead of pop-up windows",
    )
    parser.add_argument("file_path", type=Path, nargs="?", help="Exact path to the file")
    parser.add_argument("expected_hash", nargs="?", help="Expected hash in hexadecimal form")
    parser.add_argument(
        "--algorithm",
        "-a",
        choices=ALGORITHMS,
        help="Hash algorithm for --non-interactive mode",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="Bytes read at a time (default: %(default)s)",
    )
    return parser


def detect_algorithm(expected_hash: str) -> str:
    """Choose an algorithm from a conventional hexadecimal digest length."""
    hash_length = len(expected_hash.strip())
    for algorithm, config in ALGORITHMS.items():
        if hash_length == config["digest_length"]:
            return algorithm
    raise ValidationError(
        "Could not identify the hash type. Enter a 32-character MD5 or "
        "64-character SHA-256 hexadecimal hash."
    )


def prompt_for_console_inputs() -> tuple[Path, str, str]:
    """Collect checksum details in the requested hash-then-file order."""
    try:
        expected_hash = input("Expected MD5 or SHA-256 hash: ").strip()
        algorithm = detect_algorithm(expected_hash)
        file_path = Path(input("Exact file path: ").strip())
    except EOFError as error:
        raise ValidationError("Input was cancelled.") from error
    return file_path, expected_hash, algorithm


def apple_script_string(value: str) -> str:
    """Return a safely quoted AppleScript string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ask_for_macos_value(title: str, prompt: str) -> str:
    """Request one value through a native macOS dialog with a text field."""
    script = f"""
        try
            set response to display dialog {apple_script_string(prompt)} ¬
                with title {apple_script_string(title)} ¬
                default answer "" ¬
                buttons {{"Cancel", "Continue"}} ¬
                default button "Continue" cancel button "Cancel"
            return text returned of response
        on error number -128
            return "__CANCELLED__"
        end try
    """
    completed = subprocess.run(
        ["osascript", "-e", script], capture_output=True, text=True, check=False
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or value == "__CANCELLED__":
        raise ValidationError("Validation was cancelled or the input window could not open.")
    return value


def ask_for_window_value(title: str, prompt: str) -> str:
    """Show one standalone focused input window and return its value."""
    import tkinter as tk

    dialog = tk.Tk()
    dialog.title(title)
    dialog.resizable(False, False)
    dialog.minsize(560, 150)

    frame = tk.Frame(dialog, padx=20, pady=18)
    frame.pack()
    tk.Label(frame, text=prompt, anchor="w").pack(fill="x")
    entry = tk.Entry(frame, width=78, state="normal", takefocus=True)
    entry.pack(fill="x", pady=(8, 14))

    result: list[str | None] = [None]

    def submit() -> None:
        result[0] = entry.get().strip()
        dialog.quit()

    def cancel() -> None:
        dialog.quit()

    tk.Button(frame, text="Continue", command=submit, default="active").pack()
    dialog.protocol("WM_DELETE_WINDOW", cancel)
    dialog.bind("<Return>", lambda _event: submit())
    dialog.bind("<Escape>", lambda _event: cancel())

    def activate_input() -> None:
        """Bring this application window forward and place the caret in Entry."""
        dialog.deiconify()
        dialog.lift()
        dialog.focus_force()
        entry.focus_set()
        entry.focus_force()

    entry.bind("<Button-1>", lambda _event: entry.focus_force())
    dialog.bind("<Button-1>", lambda _event: entry.focus_force())
    dialog.after_idle(activate_input)
    dialog.mainloop()
    dialog.destroy()

    if result[0] is None:
        raise ValidationError("Validation was cancelled.")
    return result[0]


def prompt_for_window_inputs() -> tuple[Path, str, str]:
    """Collect checksum details through focused hash-then-file pop-up windows."""
    try:
        ask_for_value = ask_for_macos_value if platform.system() == "Darwin" else ask_for_window_value

        expected_hash = ask_for_value(
            "Please provide Hash",
            "Enter the expected MD5 or SHA-256 hash, then press Enter:",
        )
        algorithm = detect_algorithm(expected_hash)
        file_location = ask_for_value(
            "Please provide File Location",
            "Enter the exact file path, then press Enter:",
        )
        return Path(file_location.strip()), expected_hash, algorithm
    except (OSError, subprocess.SubprocessError) as error:
        raise ValidationError(
            "Could not open input windows. Run with --console to use terminal prompts."
        ) from error


def show_result_window(is_valid: bool, file_path: Path, algorithm: str) -> None:
    """Display the completed validation status in the final pop-up window."""
    if platform.system() == "Darwin":
        status = "VALID" if is_valid else "NOT VALID"
        script = f"""
            display dialog {apple_script_string(status)} ¬
                with title "Hash Validation Result" ¬
                buttons {{"Close"}} default button "Close"
        """
        subprocess.run(["osascript", "-e", script], check=False)
        return

    import tkinter as tk

    window = tk.Tk()
    window.title("Hash Validation Result")
    window.resizable(False, False)
    status = "VALID" if is_valid else "NOT VALID"
    frame = tk.Frame(window, padx=20, pady=18)
    frame.pack()
    tk.Label(frame, text=status, font=("TkDefaultFont", 16, "bold")).pack(pady=(0, 10))
    tk.Label(
        frame,
        text=f"File: {file_path}\nAlgorithm: {ALGORITHMS[algorithm]['label']}",
        justify="left",
    ).pack()
    tk.Button(frame, text="Close", command=window.destroy, default="active").pack(pady=(16, 0))
    window.protocol("WM_DELETE_WINDOW", window.destroy)
    window.lift()
    window.mainloop()


def main() -> int:
    args = build_parser().parse_args()

    try:
        if args.non_interactive:
            if args.file_path is None or args.expected_hash is None or args.algorithm is None:
                raise ValidationError(
                    "Non-interactive mode requires FILE_PATH, EXPECTED_HASH, and --algorithm."
                )
            file_path = args.file_path
            expected_hash = args.expected_hash
            algorithm = args.algorithm.lower()
        else:
            file_path, expected_hash, algorithm = (
                prompt_for_console_inputs() if args.console else prompt_for_window_inputs()
            )

        is_valid, calculated_hash, file_size = validate_file(
            file_path, expected_hash, algorithm, args.chunk_size
        )
    except (ValidationError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    print(f"File: {file_path}")
    print(f"Size: {file_size:,} bytes")
    print(f"Algorithm: {ALGORITHMS[algorithm]['label']}")
    print(f"Expected: {normalize_expected_hash(expected_hash, algorithm)}")
    print(f"Calculated: {calculated_hash}")
    print(f"Result: {'VALID' if is_valid else 'INVALID'}")
    if not args.non_interactive and not args.console:
        show_result_window(is_valid, file_path, algorithm)
    return 0 if is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
