
# SOCKS5 server

[![](https://img.shields.io/github/license/totravel/socks5-server-c)](https://github.com/totravel/socks5-server-c/blob/master/LICENSE)

一个 C 语言实现的轻量级 SOCKS5 代理服务器。

- 仅支持 TCP 代理
- 支持代理域名解析
- 支持用户名密码认证方式
- 可指定代理服务绑定的 IP 地址和端口号

## 构建

执行以下命令即可。

```bash
$ make
```

若跟上 `D=1` 可构建一个在运行时有详细输出的版本。

```bash
$ make D=1
```

## 用法

执行以下命令即可启动 SOCKS5 代理服务，默认监听 1080 端口，无需认证。

```bash
$ ./server
Listen to port 1080 on 0.0.0.0
No authentication.
```

带上 `-h` 选项可以查看帮助信息。

```bash
$ ./server -h
usage: ./server [-a addr] [-p port] [-u path/to/passwd] [-d]
options: 
  -a <ip address>      Bind to this address (default: 0.0.0.0)
  -p <port number>     Bind to this port (default: 1080)
  -u <path/to/passwd>  Each row of passwd describes a user.
                       e.g. admin,secret
  -d                   Run as a daemon.
  -h                   Show this help message.
```

选项 `-a` 和 `-p` 分别用来指定代理服务绑定的 IP 地址和端口号。

```bash
$ ./server -a 127.0.0.1 -p 8080
Listen to port 8080 on 127.0.0.1
No authentication.
```

带上选项 `-u` 可将代理服务设为要求用户名密码认证，选项后面必须跟上一个文件的路径，该文件的每一行包含一个用户的用户名和密码，用户名和密码之间用逗号 `,` 隔开，例如：

```bash
$ cat ./passwd
admin,secret
user1,123456
user2,123123
user3,456456
$ ./server -u ./passwd
Listen to port 1080 on 0.0.0.0
Using username/password authentication.
```

若带上 `-d` 参数，代理服务器将脱离终端，成为守护进程。

```bash
$ ./server -d
Listen to port 1080 on 0.0.0.0
No authentication.
Server pid is: [xxxx]
```

## License

本项目遵循 [MIT](https://github.com/totravel/socks5-server-c/blob/master/LICENSE) 开源协议发布。
