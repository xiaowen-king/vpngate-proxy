import base64
import csv
import io
import json
import os
import re
import socket
import subprocess
import threading
import time
import logging
import requests
import ipaddress
from collections import OrderedDict
from socks_server import Socks5Server
from datetime import datetime, timezone, timedelta
import uuid

logger = logging.getLogger("vpn_manager")

# ---------- 常量限制 ----------
MAX_HISTORY_RECORDS = 500       # 连接历史最大条数，防止磁盘/内存无限增长
MAX_FAILED_IPS = 1000           # 失败 IP 黑名单最大条数，防止 set 无限膨胀
MAX_CONNECT_ATTEMPTS = 50       # 单次 auto_connect_next 最多尝试的节点数，防止风暴循环
NODE_CONFIG_CACHE_MAX = 200     # 节点配置缓存最大条数（仅缓存最近使用过的）


class VpnManager:
    def __init__(self):
        self.config = self._load_config_safe()
        self.nodes = []
        self.current_node = None
        self.vpn_process = None
        self.socks_server = None
        self.status = {
            "connected": False,
            "node_info": {},
            "ip_info": None,
            "socks": "",
            "connected_since": None
        }
        self._stop_event = threading.Event()
        self._health_thread = None
        self._bg_check_thread = None
        self._auto_update_thread = None
        self._auto_update_trigger = threading.Event()
        self._log_callback = None
        self.tun_dev = None
        self.tun_ip = None
        self.vpn_gateway = None
        self.health_fail_count = 0
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self.health_check_interval = self.config.get("health_check_interval", 10)
        self._available_nodes = []
        self.policy_routing_set = False
        self._failed_ips = set()
        self.preferred_nodes = self.config.get("preferred_nodes", [])
        self.history_file = "/data/connection_history.json"
        self.connection_history = self._load_history()
        self._history_clean_thread = None
        self._reconnect_fail_count = 0
        self.reconnect_interval = self.config.get("reconnect_interval", 30)
        # 节点配置缓存：IP → openvpn_config_base64，仅缓存最近使用过的节点
        self._node_config_cache = OrderedDict()
        # 线程安全锁
        self._state_lock = threading.Lock()
        # 线程启动标志，防止重复创建线程
        self._threads_started = False

    @staticmethod
    def _load_config_safe():
        import config as cfg_module
        return cfg_module.load_config()

    def set_log_callback(self, cb):
        self._log_callback = cb

    def log(self, message):
        logger.info(message)
        if self._log_callback:
            self._log_callback(message)

    def set_config(self, cfg):
        import config as cfg_module
        if "preferred_nodes" not in cfg:
            cfg["preferred_nodes"] = self.config.get("preferred_nodes", [])
        self.config = cfg
        cfg_module.save_config(cfg)
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self.health_check_interval = self.config.get("health_check_interval", 10)
        self.reconnect_interval = self.config.get("reconnect_interval", 30)
        self.preferred_nodes = self.config.get("preferred_nodes", [])
        self._auto_update_trigger.set()

    def fetch_nodes(self):
        self.log("正在获取节点列表...")
        try:
            api_url = self.config.get("api_url", "")
            if not api_url:
                self.log("API 地址未配置，跳过获取节点")
                return
            resp = requests.get(api_url, timeout=30)
            resp.encoding = "utf-8"
            text = resp.text
            lines = text.splitlines()

            header_index = None
            for i, line in enumerate(lines):
                if line.strip().startswith("#HostName"):
                    header_index = i
                    break

            if header_index is None:
                self.log("未找到节点表头，可能 API 格式变化")
                return

            csv_lines = [lines[header_index]]
            for line in lines[header_index+1:]:
                if line.strip() == "":
                    continue
                csv_lines.append(line)

            csv_text = "\n".join(csv_lines)
            reader = csv.DictReader(io.StringIO(csv_text))
            nodes = []
            for row in reader:
                if not row.get("#HostName"):
                    continue
                nodes.append({
                    "hostname": row.get("#HostName", ""),
                    "ip": row.get("IP", ""),
                    "score": row.get("Score", ""),
                    "ping": row.get("Ping", ""),
                    "speed": row.get("Speed", ""),
                    "country_long": row.get("CountryLong", ""),
                    "country_short": row.get("CountryShort", ""),
                    "num_sessions": row.get("NumVpnSessions", ""),
                    "uptime": row.get("Uptime", ""),
                    "total_users": row.get("TotalUsers", ""),
                    "total_traffic": row.get("TotalTraffic", ""),
                    "log_type": row.get("LogType", ""),
                    "operator": row.get("Operator", ""),
                    "message": row.get("Message", ""),
                    "openvpn_config_base64": row.get("OpenVPN_ConfigData_Base64", "")
                })
            self.nodes = nodes
            self.log(f"获取到 {len(nodes)} 个节点")
        except Exception as e:
            self.log(f"获取节点列表失败: {str(e)}")

    def filter_nodes(self, region="all"):
        nodes = list(self.nodes)
        if region == "all":
            return nodes
        return [n for n in nodes if (n.get("country_short") or "").upper() == region.upper()]

    def detect_ip(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,proxy,hosting,mobile,query"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if data.get("status") != "success":
                self.log(f"ip-api 查询失败: {data.get('message')}")
                return None
            return {
                "查询IP": data.get("query", ip),
                "国家": data.get("country", ""),
                "地区": data.get("regionName", ""),
                "城市": data.get("city", ""),
                "ISP": data.get("isp", ""),
                "代理/VPN": "是" if data.get("proxy") else "否",
                "机房/托管": "是" if data.get("hosting") else "否",
                "移动网络": "是" if data.get("mobile") else "否",
            }
        except Exception as e:
            self.log(f"IP检测失败: {str(e)}")
            return None

    def test_node(self, node):
        return True

    def _get_tun_info(self):
        try:
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
            matches = re.findall(r"(tun\d+):\s.*?\n\s+inet (\d+\.\d+\.\d+\.\d+)", result.stdout, re.DOTALL)
            if matches:
                dev, ip = matches[-1]
                return ip, dev
        except Exception:
            pass
        return None, None

    def _setup_policy_routing(self, ip, dev):
        try:
            subprocess.run(["ip", "rule", "add", "from", ip, "table", "100"], check=False)
            if self.vpn_gateway:
                subprocess.run(
                    ["ip", "route", "add", "default", "via", self.vpn_gateway, "dev", dev, "table", "100"],
                    check=False
                )
                self.log(f"策略路由已配置: from {ip} table 100 (default via {self.vpn_gateway} dev {dev})")
            else:
                subprocess.run(
                    ["ip", "route", "add", "default", "dev", dev, "table", "100"],
                    check=False
                )
                self.log(f"策略路由已配置: from {ip} table 100 (default dev {dev})")
            self.policy_routing_set = True
        except Exception as e:
            self.log(f"配置策略路由失败: {e}")

    def _teardown_policy_routing(self, ip, dev):
        if not self.policy_routing_set:
            return
        try:
            subprocess.run(["ip", "rule", "del", "from", ip, "table", "100"], check=False)
            if self.vpn_gateway:
                subprocess.run(
                    ["ip", "route", "del", "default", "via", self.vpn_gateway, "dev", dev, "table", "100"],
                    check=False
                )
            else:
                subprocess.run(
                    ["ip", "route", "del", "default", "dev", dev, "table", "100"],
                    check=False
                )
            self.log("策略路由已清理")
        except Exception as e:
            self.log(f"清理策略路由失败: {e}")

    def _get_node_config(self, node):
        """获取节点的 OpenVPN 配置 base64，优先从内存中的节点数据获取，其次从缓存获取"""
        config_b64 = node.get("openvpn_config_base64")
        if config_b64:
            return config_b64
        # 从缓存中查找
        ip = node.get("ip")
        if ip and ip in self._node_config_cache:
            return self._node_config_cache[ip]
        return None

    def _cache_node_config(self, node):
        """将节点的 OpenVPN 配置缓存起来，供后续重连使用"""
        ip = node.get("ip")
        config_b64 = node.get("openvpn_config_base64")
        if ip and config_b64:
            if ip in self._node_config_cache:
                # 已存在则移到末尾（最近使用）
                self._node_config_cache.move_to_end(ip)
            else:
                # 限制缓存大小，防止内存无限增长
                if len(self._node_config_cache) >= NODE_CONFIG_CACHE_MAX:
                    self._node_config_cache.popitem(last=False)  # 移除最早的
                self._node_config_cache[ip] = config_b64

    def connect_node(self, node):
        self.disconnect()
        time.sleep(0.5)
        self.current_node = node
        hostname = node.get("hostname", "未知")
        ip = node.get("ip", "")
        if not ip:
            self.log("节点数据异常：缺少 IP 地址")
            return False
        self.log(f"正在连接到节点: {hostname} ({ip})")

        # 获取 OpenVPN 配置
        config_b64 = self._get_node_config(node)
        if not config_b64:
            self.log("未找到节点 OpenVPN 配置，无法连接")
            self._add_failed_ip(ip)
            return False

        # 缓存配置供后续重连使用
        self._cache_node_config({"ip": ip, "openvpn_config_base64": config_b64})

        try:
            ovpn_content = base64.b64decode(config_b64).decode("utf-8")
        except Exception:
            self.log("解码 OpenVPN 配置失败")
            self._add_failed_ip(ip)
            return False

        auth_path = "/tmp/vpn_auth.txt"
        with open(auth_path, "w") as f:
            f.write(f"{self.config.get('vpn_user', '')}\n{self.config.get('vpn_pass', '')}\n")

        if "auth-user-pass" not in ovpn_content:
            ovpn_content += f"\nauth-user-pass {auth_path}\n"

        ovpn_content += "\nroute-nopull\n"
        ovpn_content += "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n"

        ovpn_path = "/tmp/vpn_config.ovpn"
        with open(ovpn_path, "w") as f:
            f.write(ovpn_content)

        try:
            self.vpn_process = subprocess.Popen(
                ["openvpn", "--config", ovpn_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            self.log(f"启动 OpenVPN 失败: {str(e)}")
            self._add_failed_ip(ip)
            return False

        tun_ip = None
        tun_dev = None
        vpn_gateway = None
        connected_flag = False
        start_time = time.time()
        timeout = 25

        while time.time() - start_time < timeout:
            if self.vpn_process.poll() is not None:
                self.log("OpenVPN 进程已退出，连接失败")
                self._add_failed_ip(ip)
                self._cleanup_vpn_process()
                return False

            line = self.vpn_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            self.log(f"[OpenVPN] {line.strip()}")

            if "Peer Connection Initiated" in line:
                self.log("TLS 握手成功，等待配置...")

            if "PUSH: Received control message: 'PUSH_REPLY" in line:
                match = re.search(r"ifconfig (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    vpn_gateway = match.group(2)
                    self.log(f"提取到 VPN 网关 IP: {vpn_gateway}")

            if "Initialization Sequence Completed" in line:
                connected_flag = True
                self.log("OpenVPN 初始化完成")
                break

            if "net_addr_ptp_v4_add" in line:
                match = re.search(r"net_addr_ptp_v4_add: (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    tun_ip = match.group(1)
                    self.log(f"从 OpenVPN 日志获取到 VPN IP: {tun_ip}")

        if connected_flag or tun_ip:
            self.log("正在从系统获取 VPN 接口信息...")
            sys_ip, sys_dev = self._get_tun_info()
            if sys_ip:
                tun_ip = sys_ip
                tun_dev = sys_dev
            else:
                self.log("无法从系统获取 VPN IP")
                self._add_failed_ip(ip)
                self.disconnect()
                return False
        else:
            self.log("获取 VPN IP 失败，无法启动 SOCKS5 代理")
            self._add_failed_ip(ip)
            self.disconnect()
            return False

        self.tun_dev = tun_dev
        self.tun_ip = tun_ip
        self.vpn_gateway = vpn_gateway
        self.health_fail_count = 0

        self._setup_policy_routing(tun_ip, tun_dev)
        time.sleep(1)
        self.log(f"VPN 连接成功，本机 VPN IP: {tun_ip}, 接口: {tun_dev}, 网关: {vpn_gateway}")

        socks_bind = "0.0.0.0"
        socks_port = self.config.get("socks_port", 1080)
        max_conn = self.config.get("socks_max_connections", 200)
        self.socks_server = Socks5Server(socks_bind, socks_port, tun_ip, max_connections=max_conn)
        self.socks_server.start()

        # 隧道预热：通过 SOCKS5 发一个测试请求，激活 VPN 隧道的 TLS 会话和路由
        # 防止浏览器第一个 HTTPS 请求因隧道未完全就绪而失败（ERR_CONNECTION_CLOSED）
        self._warmup_tunnel(socks_port)

        self.status["connected"] = True
        self.status["node_info"] = node
        self.status["socks"] = f"socks5://{self._get_host_ip()}:{socks_port}"
        self.status["ip_info"] = self.detect_ip(ip)
        self.log(f"SOCKS5 代理已启动: {self.status['socks']}")

        self.status["connected_since"] = datetime.now(timezone.utc).isoformat()
        self.log(f"已记录连接开始时间: {self.status['connected_since']}")
        self.add_connection_record(node)
        self._failed_ips.clear()                      # 连接成功清空整个黑名单，让优先节点下次可用
        self._reconnect_fail_count = 0
        return True

    def _cleanup_vpn_process(self):
        """安全清理 OpenVPN 进程，防止僵尸/孤儿进程"""
        proc = self.vpn_process
        self.vpn_process = None
        if proc is None:
            return
        try:
            proc.terminate()
            try:
                proc.stdout.close()
            except Exception:
                pass
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                proc.wait(timeout=3)
            except Exception:
                pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def disconnect(self):
        if self.status.get("connected_since") and self.status.get("node_info"):
            try:
                start = datetime.fromisoformat(self.status["connected_since"])
                duration = datetime.now(timezone.utc) - start
                duration_str = str(duration).split('.')[0]
                hostname = self.status["node_info"].get("hostname", "")
                ip = self.status["node_info"].get("ip", "")
                self.log(f"节点 {hostname} ({ip}) 已断开，使用时长: {duration_str}")
            except Exception as e:
                self.log(f"记录使用时长异常: {e}")
        self.status["connected_since"] = None

        if self.status.get("node_info") and self.status["node_info"].get("ip"):
            self.update_connection_record_end(self.status["node_info"]["ip"])

        if self.tun_ip and self.tun_dev:
            self._teardown_policy_routing(self.tun_ip, self.tun_dev)

        self._cleanup_vpn_process()

        if self.socks_server:
            self.socks_server.stop()
            self.socks_server = None
        self.tun_dev = None
        self.tun_ip = None
        self.vpn_gateway = None
        self.status["connected"] = False
        self.status["node_info"] = {}
        self.status["socks"] = ""
        self.policy_routing_set = False

    def _warmup_tunnel(self, socks_port):
        """隧道预热：通过 SOCKS5 发一个轻量请求，激活 VPN 隧道的 TLS 会话和路由缓存。
        防止浏览器第一个 HTTPS 请求因隧道未完全就绪而失败。"""
        try:
            self.log("正在预热 VPN 隧道...")
            result = subprocess.run(
                ["curl", "-s", "--socks5", f"127.0.0.1:{socks_port}",
                 "--max-time", "10", "--connect-timeout", "5",
                 "-o", "/dev/null", "-w", "%{http_code}",
                 "http://httpbin.org/ip"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                self.log(f"隧道预热成功 (HTTP {result.stdout.strip()})")
            else:
                # 预热失败不影响连接状态，只是警告
                self.log(f"隧道预热未成功: {result.stderr.strip() or '无响应'}")
        except Exception as e:
            self.log(f"隧道预热异常（不影响连接）: {e}")

    def _get_host_ip(self):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
        except Exception:
            return "127.0.0.1"
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    def _load_history(self):
        if not os.path.exists(self.history_file):
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_history(self):
        try:
            # 原子写入历史文件，防止写入中途崩溃导致数据损坏
            import tempfile
            dir_name = os.path.dirname(self.history_file) or "."
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.connection_history, f, indent=2, ensure_ascii=False)
                os.replace(tmp_path, self.history_file)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            self.log(f"保存连接历史失败: {e}")

    def add_connection_record(self, node_info):
        record = {
            "id": str(uuid.uuid4())[:8],
            "hostname": node_info.get("hostname", ""),
            "ip": node_info.get("ip", ""),
            "country": node_info.get("country_long", ""),
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": None,
            "duration": None
        }
        with self._state_lock:
            self.connection_history.insert(0, record)
            # 限制历史记录数量，防止磁盘/内存无限增长
            if len(self.connection_history) > MAX_HISTORY_RECORDS:
                self.connection_history = self.connection_history[:MAX_HISTORY_RECORDS]
            self._save_history()

    def update_connection_record_end(self, node_ip, end_time=None):
        if not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._state_lock:
            for rec in self.connection_history:
                if rec.get("ip") == node_ip and rec.get("end_time") is None:
                    rec["end_time"] = end_time
                    try:
                        start = datetime.strptime(rec["start_time"], "%Y-%m-%d %H:%M:%S")
                        duration = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") - start
                        rec["duration"] = str(duration).split('.')[0]
                    except Exception:
                        rec["duration"] = None
                    self._save_history()
                    return

    def delete_connection_record(self, record_id):
        with self._state_lock:
            self.connection_history = [r for r in self.connection_history if r["id"] != record_id]
            self._save_history()

    def clean_old_history(self):
        retention_days = self.config.get("connection_history_retention_days", 30)
        cutoff = datetime.now() - timedelta(days=retention_days)
        with self._state_lock:
            before_count = len(self.connection_history)
            cleaned = []
            for r in self.connection_history:
                try:
                    start_str = r.get("start_time")
                    if not start_str:
                        continue  # 无时间戳的脏数据直接丢弃
                    if datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S") > cutoff:
                        cleaned.append(r)
                except (ValueError, TypeError):
                    continue  # 时间格式异常的脏数据直接丢弃
            self.connection_history = cleaned
            after_count = len(self.connection_history)
            if before_count != after_count:
                self.log(f"清理过期连接记录: {before_count} → {after_count}")
            self._save_history()

    def _history_clean_loop(self):
        while not self._stop_event.is_set():
            # 每 6 小时清理一次，使用 wait 替代循环 sleep，收到停止信号立即返回
            self._stop_event.wait(21600)
            if self._stop_event.is_set():
                return
            self.clean_old_history()

    def _add_failed_ip(self, ip):
        """添加失败 IP，限制集合大小防止无限增长"""
        self._failed_ips.add(ip)
        if len(self._failed_ips) > MAX_FAILED_IPS:
            # 超过上限时清空一半（set 无序，无法精确保留"最近的"，但配合定期 clear 不影响功能）
            self._failed_ips.clear()
            self._failed_ips.add(ip)  # 保留当前这个

    def _is_tunnel_alive(self):
        # ---- 第一层：检查 OpenVPN 进程 ----
        if not self.vpn_process or self.vpn_process.poll() is not None:
            self.log("健康检测失败: OpenVPN 进程未运行")
            return False

        # ---- 第二层：检查 tun 接口和 IP（快速失败，避免无意义的 HTTP 检测） ----
        if not self.tun_dev or not self.tun_ip:
            self.log("健康检测失败: tun 接口未分配 IP")
            return False
        try:
            ip_check = subprocess.run(
                ["ip", "addr", "show", "dev", self.tun_dev],
                capture_output=True, text=True, timeout=5
            )
            if ip_check.returncode != 0:
                self.log(f"健康检测失败: tun 接口 {self.tun_dev} 不存在 (可能 VPN 隧道已断开)")
                return False
            if self.tun_ip not in ip_check.stdout:
                self.log(f"健康检测失败: tun 接口 {self.tun_dev} 上的 IP {self.tun_ip} 已丢失 (VPN 隧道断开)")
                return False
        except Exception as e:
            self.log(f"健康检测失败: 检查 tun 接口异常 - {e}")
            return False

        # ---- 第三层：通过 SOCKS5 代理访问检测 URL ----
        raw_urls = self.config.get("health_check_urls", "")
        if raw_urls.strip():
            urls = [u.strip() for u in re.split(r'[,\n]', raw_urls) if u.strip()]
            urls = [u if u.startswith('http://') or u.startswith('https://') else f'http://{u}' for u in urls]
        else:
            urls = [
                "http://httpbin.org/ip",
                "http://ifconfig.me",
                "http://www.google.com"
            ]

        socks_port = self.config.get("socks_port", 1080)
        timeout = self.config.get("health_check_timeout", 8)
        if not isinstance(timeout, (int, float)) or timeout < 3:
            timeout = 8

        for url in urls:
            try:
                result = subprocess.run(
                    ["curl", "-s", "--socks5", f"127.0.0.1:{socks_port}",
                     "--max-time", str(timeout), "-w", "\n%{http_code}", url],
                    capture_output=True, text=True, timeout=timeout + 3
                )
                output = result.stdout.strip()
                if result.returncode == 0 and output:
                    # 分离 HTTP 状态码和响应体
                    lines = output.rsplit('\n', 1)
                    body = lines[0] if len(lines) > 1 else output
                    http_code = lines[-1] if len(lines) > 1 else ""
                    if body.strip():
                        self.log(f"健康检测成功: {url} 访问正常 (HTTP {http_code})")
                        return True
                    else:
                        self.log(f"健康检测尝试 {url} 失败: 连接成功但无响应数据 (HTTP {http_code})")
                elif result.returncode == 7:
                    # curl exit code 7 = couldn't connect to host
                    self.log(f"健康检测尝试 {url} 失败: SOCKS5 代理连接失败 (隧道可能断开)")
                else:
                    self.log(f"健康检测尝试 {url} 失败: {result.stderr.strip() or f'curl 退出码 {result.returncode}'}")
            except subprocess.TimeoutExpired:
                self.log(f"健康检测尝试 {url} 超时 ({timeout}秒)")
            except Exception as e:
                self.log(f"健康检测尝试 {url} 异常: {e}")

        self.log("健康检测失败: 所有检测地址均无法访问")
        return False

    def measure_latency(self):
        if not self.tun_dev or not self.tun_ip:
            return -1

        target = self.config.get("latency_check_target", "").strip()
        if not target:
            target = self.vpn_gateway if self.vpn_gateway else "8.8.8.8"

        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", "-I", self.tun_dev, target],
                capture_output=True, text=True, timeout=5
            )
            if "time=" in result.stdout:
                match = re.search(r"time=(\d+\.?\d*) ms", result.stdout)
                if match:
                    return round(float(match.group(1)), 1)
            return -1
        except Exception:
            return -1

    # ============ 健康检查循环 ============
    def health_check_loop(self):
        last_reconnect_time = 0
        while not self._stop_event.is_set():
            time.sleep(self.health_check_interval)
            if self._stop_event.is_set():
                break
            if not self.status["connected"]:
                self.health_fail_count = 0
                now = time.time()
                if now - last_reconnect_time > self.reconnect_interval:
                    self.log("检测到未连接，尝试自动重连...")
                    success, msg = self.auto_connect_next()
                    if success:
                        self.log(f"自动重连成功: {msg}")
                        self._reconnect_fail_count = 0
                    else:
                        self.log(f"自动重连失败: {msg}")
                        self._reconnect_fail_count += 1
                        if self._reconnect_fail_count >= 3:
                            self.log("自动重连连续失败3次，清空IP黑名单以便重新尝试所有节点")
                            self._failed_ips.clear()
                            self._reconnect_fail_count = 0
                    last_reconnect_time = now
                continue

            if self._is_tunnel_alive():
                self.health_fail_count = 0
                self._reconnect_fail_count = 0
            else:
                self.health_fail_count += 1
                self.log(f"健康检测失败 (连续 {self.health_fail_count} 次)")

            if self.health_fail_count >= self.max_health_fails:
                self.log(f"连续 {self.health_fail_count} 次健康检测失败，准备切换节点")
                self._switch_to_next_available()
                self.health_fail_count = 0

    def background_check_nodes(self):
        """后台节点扫描（目前 test_node 始终返回 True，此线程仅预热节点列表）"""
        while not self._stop_event.is_set():
            # 每 5 分钟扫描一次，而非 60 秒，减少无意义 CPU 开销
            for _ in range(300):
                if self._stop_event.is_set():
                    return
                time.sleep(1)
            nodes = self.filter_nodes(self.config.get("region", "all"))
            available = []
            check_limit = self.config.get("check_limit", 20)
            for node in nodes[:check_limit]:
                if self._stop_event.is_set():
                    return
                if self.status["connected"] and node.get("ip") == self.status["node_info"].get("ip"):
                    continue
                if self.test_node(node):
                    available.append(node)
            self._available_nodes = available

    def _auto_update_loop(self):
        while not self._stop_event.is_set():
            interval_min = self.config.get("auto_update_interval", 0)
            if interval_min <= 0:
                self._auto_update_trigger.wait(3600)
                self._auto_update_trigger.clear()
                continue
            interval_sec = interval_min * 60
            self._auto_update_trigger.wait(interval_sec)
            self._auto_update_trigger.clear()
            if self._stop_event.is_set():
                break
            current_interval = self.config.get("auto_update_interval", 0)
            if current_interval <= 0:
                continue
            self.fetch_nodes()

    # ============ 切换节点 ============
    def _switch_to_next_available(self):
        self.log("准备切换节点...")
        success, msg = self.auto_connect_next()
        if success:
            self.log(f"切换成功: {msg}")
        else:
            self.log(f"切换失败: {msg}")

    # ============ 自动连接下一个节点（优先节点优先） ============
    def auto_connect_next(self):
        """
        自动连接下一个可用节点。
        策略：
        1. 如果设置了优先节点，始终优先从它们之中选择（跳过当前IP）。
        2. 若所有优先节点均不可用（连接失败或已在黑名单），则降级到普通节点列表。
        3. 普通节点列表根据地区、子网优先等设置筛选。
        4. 限制最大尝试次数，防止风暴循环。
        """
        # 获取当前连接（或最后尝试）的IP
        last_ip = None
        if self.current_node:
            last_ip = self.current_node.get("ip")
        elif self.status["node_info"].get("ip"):
            last_ip = self.status["node_info"]["ip"]

        attempt_count = 0

        # ---------- 优先节点循环 ----------
        if self.preferred_nodes:
            self.log("正在尝试优先节点...")
            start_idx = 0
            if last_ip:
                for i, node in enumerate(self.preferred_nodes):
                    if node.get("ip") == last_ip:
                        start_idx = i + 1
                        break

            # 第一轮：尝试所有非当前IP且不在黑名单的优先节点
            for i in range(len(self.preferred_nodes)):
                if self._stop_event.is_set():
                    break
                if attempt_count >= MAX_CONNECT_ATTEMPTS:
                    self.log(f"已达到最大尝试次数 ({MAX_CONNECT_ATTEMPTS})，停止尝试")
                    return False, "达到最大尝试次数"
                idx = (start_idx + i) % len(self.preferred_nodes)
                node = self.preferred_nodes[idx]
                node_ip = node.get("ip", "")
                node_hostname = node.get("hostname", "未知")
                if node_ip == last_ip:
                    continue
                if node_ip in self._failed_ips:
                    continue
                attempt_count += 1
                self.log(f"尝试优先节点: {node_hostname} ({node_ip})")
                self._add_failed_ip(node_ip)
                if self.connect_node(node):
                    return True, node_hostname

            # 如果第一轮全部因为黑名单或失败而跳过，尝试临时清空黑名单再试一次
            self.log("优先节点全部跳过或失败，临时清空黑名单再尝试一次...")
            self._failed_ips.clear()
            for i in range(len(self.preferred_nodes)):
                if self._stop_event.is_set():
                    break
                if attempt_count >= MAX_CONNECT_ATTEMPTS:
                    break
                idx = (start_idx + i) % len(self.preferred_nodes)
                node = self.preferred_nodes[idx]
                node_ip = node.get("ip", "")
                node_hostname = node.get("hostname", "未知")
                if node_ip == last_ip:
                    continue
                attempt_count += 1
                self.log(f"再次尝试优先节点: {node_hostname} ({node_ip})")
                if self.connect_node(node):
                    return True, node_hostname

            self.log("所有优先节点均连接失败，降级到普通节点列表...")

        # ---------- 普通节点列表 ----------
        region = self.config.get("region", "all")
        nodes = self.filter_nodes(region)
        if not nodes:
            self.log("自动连接失败：当前地区没有可用节点")
            return False, "当前地区没有可用节点"

        # 确定普通节点的起始位置（跳过上次使用的IP）
        start_index = 0
        if last_ip:
            for i, node in enumerate(nodes):
                if node.get("ip") == last_ip:
                    start_index = i + 1
                    break

        prefer_same_subnet = self.config.get("prefer_same_subnet", False)
        subnet_prefix = self.config.get("subnet_prefix_length", 24)

        # 收集候选节点（不在黑名单中且不是当前IP）
        candidates = []
        for i in range(len(nodes)):
            idx = (start_index + i) % len(nodes)
            node = nodes[idx]
            if node.get("ip") == last_ip:
                continue
            if node.get("ip") in self._failed_ips:
                continue
            candidates.append(node)

        if not candidates:
            self.log("自动连接失败：没有其他可用节点")
            return False, "没有其他可用节点"

        # 同子网优先排序
        if prefer_same_subnet and last_ip:
            subnet_nodes = []
            other_nodes = []
            last_sub = self._get_subnet(last_ip, subnet_prefix)
            for node in candidates:
                node_sub = self._get_subnet(node.get("ip", ""), subnet_prefix)
                if node_sub and last_sub and node_sub == last_sub:
                    subnet_nodes.append(node)
                else:
                    other_nodes.append(node)
            candidates = subnet_nodes + other_nodes

        for node in candidates:
            if self._stop_event.is_set():
                break
            if attempt_count >= MAX_CONNECT_ATTEMPTS:
                self.log(f"已达到最大尝试次数 ({MAX_CONNECT_ATTEMPTS})，停止尝试")
                return False, "达到最大尝试次数"
            attempt_count += 1
            node_ip = node.get("ip", "")
            node_hostname = node.get("hostname", "未知")
            self._add_failed_ip(node_ip)
            self.log(f"自动连接尝试节点: {node_hostname} ({node_ip})")
            if self.connect_node(node):
                return True, node_hostname
            self.log(f"节点 {node_hostname} 连接失败")

        self.log("自动连接失败：所有候选节点均连接失败")
        return False, "所有候选节点均连接失败"

    def start(self):
        self._stop_event.clear()
        self._auto_update_trigger.clear()
        self._failed_ips.clear()
        self.fetch_nodes()

        # 先启动后台线程（健康检测、自动更新等），确保连接成功后能自动维护
        if not self._threads_started:
            self._threads_started = True
            self._health_thread = threading.Thread(target=self.health_check_loop, daemon=True)
            self._health_thread.start()
            self._bg_check_thread = threading.Thread(target=self.background_check_nodes, daemon=True)
            self._bg_check_thread.start()
            self._auto_update_thread = threading.Thread(target=self._auto_update_loop, daemon=True)
            self._auto_update_thread.start()
            self._history_clean_thread = threading.Thread(target=self._history_clean_loop, daemon=True)
            self._history_clean_thread.start()

        # 首次启动：持续尝试直到连接成功或收到停止信号
        round_count = 0
        while not self._stop_event.is_set():
            round_count += 1
            connected = False

            # 优先尝试优先节点
            if self.preferred_nodes:
                self.log(f"第 {round_count} 轮：尝试优先节点...")
                for node in self.preferred_nodes:
                    if self._stop_event.is_set():
                        break
                    self._add_failed_ip(node.get("ip", ""))
                    if self.connect_node(node):
                        connected = True
                        break
                    self.log(f"优先节点 {node.get('hostname', '未知')} 连接失败")

            # 优先节点都失败，尝试普通节点
            if not connected and not self._stop_event.is_set():
                nodes = self.filter_nodes(self.config.get("region", "all"))
                if nodes:
                    self.log(f"第 {round_count} 轮：尝试普通节点...")
                    for node in nodes:
                        if self._stop_event.is_set():
                            break
                        if self.connect_node(node):
                            connected = True
                            break
                        self.log(f"节点 {node.get('hostname', '未知')} 连接失败，尝试下一个...")
                        time.sleep(1)

            if connected:
                self.log("VPN 连接成功建立")
                break
            else:
                # 所有节点都失败，清空黑名单，等待后重试
                self._failed_ips.clear()
                retry_interval = self.config.get("reconnect_interval", 30)
                self.log(f"第 {round_count} 轮所有节点均连接失败，{retry_interval} 秒后重试...")
                self._stop_event.wait(retry_interval)

    def _get_subnet(self, ip, prefix_len=24):
        try:
            network = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
            return network.network_address
        except Exception:
            return None

    def measure_nodes_latency(self, ips):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def ping_ip(ip):
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", ip],
                    capture_output=True, text=True, timeout=5
                )
                if "time=" in result.stdout:
                    match = re.search(r"time=(\d+\.?\d*) ms", result.stdout)
                    if match:
                        return ip, round(float(match.group(1)), 1)
            except Exception:
                pass
            return ip, -1

        results = {}
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in ips]
            for future in as_completed(futures):
                ip, lat = future.result()
                results[ip] = lat
        return results

    def stop(self):
        self._stop_event.set()
        self._auto_update_trigger.set()

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._state_lock:
            for rec in self.connection_history:
                if rec.get("end_time") is None:
                    rec["end_time"] = now_str
                    try:
                        start = datetime.strptime(rec["start_time"], "%Y-%m-%d %H:%M:%S")
                        duration = datetime.strptime(now_str, "%Y-%m-%d %H:%M:%S") - start
                        rec["duration"] = str(duration).split('.')[0]
                    except Exception:
                        pass
            self._save_history()

        self.disconnect()
        # 等待后台线程退出，避免重启时线程翻倍
        threads = [self._health_thread, self._bg_check_thread,
                   self._auto_update_thread, self._history_clean_thread]
        for t in threads:
            if t and t.is_alive():
                t.join(timeout=5)
        self._threads_started = False
