import socket
import struct
import threading
import logging
from logging.handlers import TimedRotatingFileHandler
import os

# ---------- 独立错误日志配置 ----------
try:
    import config
    log_retention = config.load_config().get("log_retention_days", 3)
except Exception:
    log_retention = 3

log_dir = "/data/logs"
os.makedirs(log_dir, exist_ok=True)

logger = logging.getLogger("socks_server")
logger.setLevel(logging.INFO)

error_log_file = os.path.join(log_dir, "socks-errors.log")
# 避免重复添加 handler
if not any(isinstance(h, TimedRotatingFileHandler) and h.baseFilename == os.path.abspath(error_log_file)
           for h in logger.handlers):
    file_handler = TimedRotatingFileHandler(
        error_log_file,
        when="midnight",
        interval=1,
        backupCount=log_retention,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.ERROR)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

# 阻止错误消息传播到根 logger（主日志文件）
logger.propagate = False
# -----------------------------------------


class Socks5Server:
    """极简 SOCKS5 代理，出口流量绑定到指定接口 IP，支持最大并发连接数限制"""
    def __init__(self, bind_host, bind_port, outbound_ip, max_connections=200):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.outbound_ip = outbound_ip
        self.max_connections = max_connections
        self.active_connections = 0
        self.lock = threading.Lock()
        self.server_socket = None
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.bind_host, self.bind_port))
        self.server_socket.listen(5)
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        logger.info(f"SOCKS5 server listening on {self.bind_host}:{self.bind_port}, outbound via {self.outbound_ip}")

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        logger.info("SOCKS5 server stopped")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                with self.lock:
                    if self.active_connections >= self.max_connections:
                        client_sock.close()
                        continue
                    self.active_connections += 1
                threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
            except OSError:
                if self.running:
                    logger.exception("Accept error")
                break

    def _recv_exact(self, sock, length):
        """接收指定长度的数据"""
        data = b''
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except Exception:
                return None
        return data

    def _handle_client(self, client_sock):
        remote = None
        try:
            # ---- 握手阶段 ----
            header = self._recv_exact(client_sock, 2)
            if not header or header[0] != 0x05:
                return
            n_methods = header[1]
            methods = self._recv_exact(client_sock, n_methods)
            if not methods:
                return
            if 0x00 in methods:
                client_sock.sendall(b"\x05\x00")
            else:
                client_sock.sendall(b"\x05\xff")
                return

            # ---- 请求阶段 ----
            req_header = self._recv_exact(client_sock, 4)
            if not req_header or req_header[0] != 0x05:
                return
            cmd = req_header[1]
            if cmd != 0x01:  # 只支持 CONNECT
                self._send_reply(client_sock, 0x07)
                return

            addr_type = req_header[3]
            if addr_type == 0x01:  # IPv4
                addr_data = self._recv_exact(client_sock, 4)
                if not addr_data:
                    return
                target_addr = socket.inet_ntoa(addr_data)
            elif addr_type == 0x03:  # 域名
                name_len_byte = self._recv_exact(client_sock, 1)
                if not name_len_byte:
                    return
                name_len = name_len_byte[0]
                addr_data = self._recv_exact(client_sock, name_len)
                if not addr_data:
                    return
                target_addr = addr_data.decode()
            else:
                self._send_reply(client_sock, 0x08)
                return

            port_data = self._recv_exact(client_sock, 2)
            if not port_data:
                return
            target_port = struct.unpack(">H", port_data)[0]

            # ---- 建立到目标服务器的连接 ----
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote.bind((self.outbound_ip, 0))
            remote.connect((target_addr, target_port))
            logger.debug(f"Proxying to {target_addr}:{target_port} via {self.outbound_ip}")

            # ---- 发送成功响应 ----
            bind_addr = remote.getsockname()
            reply = struct.pack("!BBBB", 0x05, 0x00, 0x00, 0x01) + \
                    socket.inet_aton(bind_addr[0]) + \
                    struct.pack("!H", bind_addr[1])
            client_sock.sendall(reply)

            # ---- 双向转发 ----
            self._relay(client_sock, remote)
        except Exception as e:
            logger.error(f"SOCKS5 handling error: {e}")
        finally:
            # 确保 client 和 remote socket 都被关闭，防止 fd 泄漏
            for sock in (client_sock, remote):
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
            with self.lock:
                self.active_connections -= 1

    def _send_reply(self, sock, rep):
        """发送错误响应"""
        try:
            sock.sendall(struct.pack("!BBBBIH", 0x05, rep, 0x00, 0x01, 0, 0))
        except Exception:
            pass

    def _relay(self, a, b):
        """双向转发数据，任一方向关闭则结束"""
        import select
        sockets = [a, b]
        while True:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 10)
            except (select.error, ValueError):
                break
            if exceptional:
                break
            for sock in readable:
                data = sock.recv(4096)
                if not data:
                    return
                other = b if sock is a else a
                try:
                    other.sendall(data)
                except:
                    return
