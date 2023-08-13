### dependency
- idna:  处理国际化域名的编码和解码，支持将 unicode 域名转换为 ascii 编码的域名，或者反之。
- h11：纯python实现的http/1.1协议库，用于解析和生成HTTP消息
- httpcore: 是一个底层HTTP客户端，支持异步请求，基于 h11 库构建
- certifi：提供可信任的证书集合，包含了一组根证书，这些根证书由 Mozilla 维护，用于验证与HTTPS相关的链接（验证服务端的证书）
- sniffio：抓包库，支持异步IO抓包

### httpx.stream vs httpx.client
httpx.stream 告诉服务器使用分块传输的方式（Chunked Transfer：在请求头中设置 Transfer-Encoding=chunked）传输数据，httpx 内部会采用异步迭代的方式获取数据；
httpx.client 则是同步接口，会将整个文件都下载到内存中
```python
import httpx

url = "http://example.com/upload"
headers = {
    "Transfer-Encoding": "chunked",
    "Content-Type": "application/json"
}

# 构建一个异步生成器来逐块生成待发送的数据
async def data_generator():
    # 将 JSON 数据分割为块，并逐块生成
    json_data = {"key": "value"}
    chunk_size = 4096
    data = json.dumps(json_data).encode("utf-8")
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]

# 发送带有分块传输和指定JSON内容类型的HTTP请求
async def send_chunked_request():
    async with httpx.AsyncClient() as client:
        async with client.request("POST", url, headers=headers, data=data_generator()) as response:
            # 处理响应
            print(response.status_code)
            print(await response.aread())

# 运行异步请求发送函数
httpx.run(send_chunked_request)

```
### netrc file
netrc 是一个用于存储网络身份验证信息的配置文件。它是一个文本文件，通常位于用户的主目录下，并命名为 .netrc。

在 netrc 文件中，可以指定各种主机（host）和与之关联的登录凭据，包括用户名、密码和登录账号等。这样，在需要进行身份验证的网络请求中，可以通过读取 netrc 文件来获取相应的凭据信息，以便自动进行身份验证。

下面是一个示例的 netrc 文件：
```netrc
machine example.com
  login username
  password mypassword

machine ftp.example.com
  login ftpusername
  password ftppassword
```
在上述示例中，我们定义了两个主机项：example.com 和 ftp.example.com。每个主机项下面是 login 和 password 字段，分别指定了相应主机的用户名和密码。

使用 netrc 配置文件的好处是可以在脚本或应用程序中避免明文硬编码敏感的网络身份验证信息。当需要进行身份验证的网络请求时，可以通过解析 netrc 文件获取相应的凭据，实现自动化的身份验证过程。

请注意，为了确保安全性，建议将 netrc 文件的权限设置为只有当前用户可读写的方式（即权限设置为 600 或更高）以防止其他人访问敏感的凭据信息。

### 简单创建一个 http 代理服务器（FORWARD模式）
`httpx.client(proxies=proxies)`
```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    target_url = 'http://example.com/' + path  # 将 example.com 替换为目标服务器的地址
    headers = {key: value for key, value in request.headers if key != 'Host'}

    response = requests.request(
        method=request.method,
        url=target_url,
        headers=headers,
        data=request.get_data(),
        cookies=request.cookies,
        stream=True
    )

    return response.raw.read(), response.status_code, dict(response.headers.items())

if __name__ == '__main__':
    app.run()
```

### 简单创建一个 http 代理服务器（TUNNEL 模式）
```python
import http.server

class TunnelProxy(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        self.send_response(200, 'Connection Established')
        self.end_headers()
        
        # 建立与目标服务器之间的隧道连接
        self.connect_to_target()

    def connect_to_target(self):
        target_host, target_port = self.path.split(':')
        
        # 创建与目标服务器之间的套接字连接
        server_socket = self.connect_to_target_socket(target_host, int(target_port))
        
        # 在代理服务器和目标服务器之间进行数据传输
        self.transfer_data(server_socket)

    def connect_to_target_socket(self, target_host, target_port):
        import socket
        server_socket = socket.create_connection((target_host, target_port))
        return server_socket
    
    def transfer_data(self, server_socket):
        while True:
            data = self.connection.recv(4096)
            if not data:
                break
            server_socket.sendall(data)
            
            response = server_socket.recv(4096)
            if not response:
                break
            self.connection.sendall(response)

if __name__ == '__main__':
    PORT = 8080

    server_address = ('', PORT)
    httpd = http.server.HTTPServer(server_address, TunnelProxy)
    
    print(f'Tunnel Proxy Server running on port {PORT}')
    httpd.serve_forever()

```

### file upload
```python
files = {'upload-file': (None, 'text content', 'text/plain')}
```
file uploads are streaming by default

### auto update token
```python

class MyCustomAuth(httpx.Auth):
    requires_response_body = True

    def __init__(self, access_token, refresh_token, refresh_url):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.refresh_url = refresh_url

    def auth_flow(self, request):
        request.headers["X-Authentication"] = self.access_token
        response = yield request

        # token 过期了
        if response.status_code == 401:
            # 重新获取token
            refresh_response = yield self.build_refresh_request()
            self.update_tokens(refresh_response)

            # 重新发起请求
            request.headers["X-Authentication"] = self.access_token
            yield request

    # 重新获取token的请求，一般是 login api
    def build_refresh_request(self):
        # Return an `httpx.Request` for refreshing tokens.
        ...

    # 从登陆接口中获取token，并重新赋值到 self.access_token 中
    def update_tokens(self, response):
        # Update the `.access_token` and `.refresh_token` tokens
        # based on a refresh response.
        data = response.json()
        ...
```

### python 的锁
- RLock（可重入锁）
- Lock（互斥锁）
- Semaphore（信号量）
- Condition（条件锁）
- Event(事件锁)

### DH 密钥交换 和 keyfile 加密
DH 密钥交换：基于数学运算，服务端和客户端都各自生成临时的公私钥，并相互交换公钥，然后再根据数学运算得到一个相同的共享密钥，这个中间不涉及到这个共享密钥的传输，因为是双方独立计算出来的；
keyfile：对方生成一个共享密钥，用我的公钥加密，然后我自己用私钥解开，这样我就知道了这个密钥的内容了。

在TLS协商过程中，确定是使用Diffie-Hellman（DH）还是其他方法生成共享密钥是根据加密套件列表和服务器与客户端之间的协商来决定的。以下是确定使用DH或其他方法生成共享密钥的一般步骤：

客户端发送支持的加密套件列表：在ClientHello消息中，客户端会发送一个加密套件列表，其中包含了客户端支持的加密算法、密钥交换算法等。

服务器从加密套件列表中选择：服务器接收到ClientHello消息后，会从客户端提供的加密套件列表中进行选择。这些加密套件包括了不同的加密算法和密钥交换方法。

服务器选择 DH 密钥交换方法：如果服务器支持Diffie-Hellman密钥交换，并且在客户端提供的加密套件列表中选择了支持DH的加密套件，那么服务器将决定使用Diffie-Hellman密钥交换来生成共享密钥。

服务器选择其他方法：如果服务器不支持Diffie-Hellman密钥交换，或者在加密套件列表中没有选择DH相关的加密套件，那么服务器将选择其他适合的密钥交换方法，如RSA密钥交换或椭圆曲线密钥交换（ECDH）等。

因此，具体使用DH还是其他方法生成共享密钥取决于服务器支持的加密套件和算法，并根据与客户端的协商而确定。在TLS协商过程中，双方会选择最佳的加密套件和密钥交换方法，以确保安全、可靠的密钥交换和通信。

### 主密钥
在TLS协商过程中，主密钥（master secret）是通过客户端和服务器共同参与的随机数、预共享密钥（premaster secret）、握手消息等计算生成的。

具体而言，TLS使用了一个称为PRF（伪随机函数）的算法来生成主密钥。PRF算法使用了一系列输入参数，包括客户端和服务器共同参与的随机数、预共享密钥以及其他握手消息。这些输入参数确保了生成的主密钥是双方之间共享且一致的。

在经典的RSA密钥交换中，客户端生成预共享密钥，并使用服务器的公钥进行加密发送给服务器。服务器使用自己的私钥解密预共享密钥。然后，双方使用预共享密钥和随机数作为输入参数，通过PRF算法计算得到相同的主密钥。

因此，主密钥是由客户端和服务器共同生成的。双方使用相同的输入参数和密钥派生函数来计算主密钥，确保了生成的主密钥是相同的。这样，客户端和服务器可以使用该主密钥进行后续的对称加密通信，确保通信的机密性和数据完整性。

需要注意的是，主密钥只在当前TLS会话中使用，并在会话结束后被丢弃。每次建立新的TLS会话时，都会重新生成一个新的预共享密钥和主密钥，以保证通信的安全性。

### TLS 中的 common_name 以及 dns_name 
common_name和dns_names是TLS/SSL证书中使用的两个字段，用于指定证书适用的主机名或域名。它们之间的区别如下：

Common Name（通用名称）：

必填字段，是X.509格式证书中的一个属性。
通常用于指定证书适用的主机名或域名。
在过去，Common Name被广泛用于标识服务器证书的主机名。例如，对于单个主机的证书，可以将Common Name设置为主机名（如example.com）。
但现在，由于多个主机名绑定到同一个证书的情况变得越来越常见，推荐使用Subject Alternative Name（SAN）扩展字段来代替Common Name。
Subject Alternative Name（SAN）和 DNS Names（域名）：

Subject Alternative Name是X.509证书中的一个扩展字段。
SAN字段用于指定证书适用的备用主机名或域名列表。
在SAN字段中，可以包含多个DNS Names（域名），以便一张证书可以适用于多个主机名。这些主机名可以是完全限定域名（FQDN）或通配符（例如*.example.com）。
使用SAN字段提供更灵活、兼容性更好的方式来标识证书适用的主机名。现代浏览器和应用程序更倾向于使用SAN字段中的主机名来验证证书，而忽略Common Name字段。
总结起来，common_name是一种旧的方式来指定单个主机名或域名。而dns_names（在Subject Alternative Name中）则提供了更灵活和推荐的方式来指定多个主机名或域名。在实践中，最好使用dns_names字段来定义证书适用的主机名，以便满足现代浏览器和应用程序的要求，并确保与多个主机名绑定的情况下的兼容性。


### trust me 生成自签名证书
```python
import trustme

# 创建一个临时根证书
ca = trustme.CA()

# 生成自签名证书，使用临时根证书进行签名
cert = ca.issue_cert("example.com", "127.0.0.1")

# 将证书和私钥保存到文件
cert.cert_pem.write_to_path("certificate.pem")
cert.private_key_pem.write_to_path("private_key.pem")

```

### 生成CA证书并放到MAC电脑 key chain 中
对于将自己生成的CA证书添加到Mac电脑的系统根证书中，您可以按照以下步骤操作：

生成自签名的CA证书：

```python
python
import trustme

# 创建一个临时根证书
ca = trustme.CA()

# 生成自签名的CA证书
ca_cert = ca.cert_pem
ca_private_key = ca.private_key_pem
导出生成的CA证书和私钥到文件：

python
ca_cert.write_to_path("ca_certificate.pem")
ca_private_key.write_to_path("ca_private_key.pem")
```
打开Mac电脑上的“钥匙串访问”应用程序（Keychain Access）。
您可以在“实用工具”文件夹中找到该应用程序。

在“钥匙串访问”应用程序中，点击菜单栏中的“文件” -> “导入项目”，选择之前导出的ca_certificate.pem文件。

输入管理员密码以确认导入该证书。

在导入的证书列表中，找到刚才导入的CA证书，并双击打开。

在打开的证书窗口中，展开“信任”部分的选项。

对于“使用此证书时”，选择“始终信任”。

关闭证书窗口并关闭“钥匙串访问”应用程序。