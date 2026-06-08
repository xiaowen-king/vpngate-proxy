import base64
import csv
import io
import json
import os
import re
import subprocess
import threading
import time
import logging
import requests
import ipaddress
from bs4 import BeautifulSoup
import config
from socks_server import Socks5Server
from datetime import datetime, timezone
import uuid
from datetime import timedelta

logger = logging.getLogger("vpn_manager")

class VpnManager:
    def __init__(self):
        self.config = config.load_config()
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
        self._reconnect_fail_count = 0          # 连续自动重连失败计数

    def set_log_callback(self, cb):
        self._log_callback = cb

    def log(self, message):
        logger.info(message)
        if self._log_callback:
            self._log_callback(message)

    def set_config(self, cfg):
        if "preferred_nodes" not in cfg:
            cfg["preferred_nodes"] = self.config.get("preferred_nodes", [])
        self.config = cfg
        config.save_config(cfg)
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self.health_check_interval = self.config.get("health_check_interval", 10)
        self.preferred_nodes = self.config.get("preferred_nodes", [])
        self._auto_update_trigger.set()

    def fetch_nodes(self):
        self.log("正在获取节点列表...")
        try:
            resp = requests.get(self.config["api_url"], timeout=30)
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

    def connect_node(self, node):
        self.disconnect()
        time.sleep(0.5)
        self.current_node = node
        self.log(f"正在连接到节点: {node['hostname']} ({node['ip']})")

        try:
            config_b64 = node["openvpn_config_base64"]
            ovpn_content = base64.b64decode(config_b64).decode("utf-8")
        except Exception:
            self.log("解码 OpenVPN 配置失败")
            self._failed_ips.add(node["ip"])
            return False

        auth_path = "/tmp/vpn_auth.txt"
        with open(auth_path, "w") as f:
            f.write(f"{self.config['vpn_user']}\n{self.config['vpn_pass']}\n")

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
            self._failed_ips.add(node["ip"])
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
                self._failed_ips.add(node["ip"])
                self.vpn_process = None
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
            ip, dev = self._get_tun_info()
            if ip:
                tun_ip = ip
                tun_dev = dev
            else:
                self.log("无法从系统获取 VPN IP")
                self._failed_ips.add(node["ip"])
                self.disconnect()
                return False
        else:
            self.log("获取 VPN IP 失败，无法启动 SOCKS5 代理")
            self._failed_ips.add(node["ip"])
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
        socks_port = self.config["socks_port"]
        max_conn = self.config.get("socks_max_connections", 200)
        self.socks_server = Socks5Server(socks_bind, socks_port, tun_ip, max_connections=max_conn)
        self.socks_server.start()

        self.status["connected"] = True
        self.status["node_info"] = node
        self.status["socks"] = f"socks5://{self._get_host_ip()}:{socks_port}"
        self.status["ip_info"] = self.detect_ip(node["ip"])
        self.log(f"SOCKS5 代理已启动: {self.status['socks']}")

        self.status["connected_since"] = datetime.now(timezone.utc).isoformat()
        self.log(f"已记录连接开始时间: {self.status['connected_since']}")
        self.add_connection_record(node)
        self._failed_ips.clear()                      # 连接成功清空整个黑名单，让优先节点下次可用
        self._reconnect_fail_count = 0
        return True

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

        if self.vpn_process:
            self.log("断开当前连接...")
            try:
                self.vpn_process.terminate()
                try:
                    self.vpn_process.stdout.close()
                except Exception:
                    pass
                self.vpn_process.wait(timeout=3)
            except Exception:
                try:
                    self.vpn_process.kill()
                    try:
                        self.vpn_process.stdout.close()
                    except Exception:
                        pass
                    self.vpn_process.wait(timeout=3)
                except Exception:
                    pass
            self.vpn_process = None

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

    def _get_host_ip(self):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

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
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.connection_history, f, indent=2, ensure_ascii=False)
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
        self.connection_history.insert(0, record)
        self._save_history()

    def update_connection_record_end(self, node_ip, end_time=None):
        if not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for rec in self.connection_history:
            if rec["ip"] == node_ip and rec["end_time"] is None:
                rec["end_time"] = end_time
                start = datetime.strptime(rec["start_time"], "%Y-%m-%d %H:%M:%S")
                duration = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") - start
                rec["duration"] = str(duration).split('.')[0]
                self._save_history()
                return

    def delete_connection_record(self, record_id):
        self.connection_history = [r for r in self.connection_history if r["id"] != record_id]
        self._save_history()

    def clean_old_history(self):
        retention_days = self.config.get("connection_history_retention_days", 30)
        cutoff = datetime.now() - timedelta(days=retention_days)
        self.connection_history = [r for r in self.connection_history if
                                   datetime.strptime(r["start_time"], "%Y-%m-%d %H:%M:%S") > cutoff]
        self._save_history()

    def _history_clean_loop(self):
        while not self._stop_event.is_set():
            time.sleep(86400)
            if self._stop_event.is_set():
                break
            self.clean_old_history()

    def _is_tunnel_alive(self):
        if not self.vpn_process or self.vpn_process.poll() is not None:
            self.log("健康检测失败: OpenVPN 进程未运行")
            return False
        if not self.tun_dev or not self.tun_ip:
            self.log("健康检测失败: tun 接口未分配 IP")
            return False
        try:
            ip_check = subprocess.run(
                ["ip", "addr", "show", "dev", self.tun_dev],
                capture_output=True, text=True, timeout=5
            )
            if ip_check.returncode != 0 or self.tun_ip not in ip_check.stdout:
                self.log("健康检测失败: tun 接口状态异常")
                return False
        except Exception as e:
            self.log(f"健康检测失败: 检查 tun 接口异常 - {e}")
            return False

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
                     "--max-time", str(timeout), url],
                    capture_output=True, text=True, timeout=timeout + 3
                )
                if result.returncode == 0 and result.stdout.strip():
                    self.log(f"健康检测成功: {url} 访问正常")
                    return True
                else:
                    self.log(f"健康检测尝试 {url} 失败: {result.stderr.strip() or '无返回数据'}")
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

    # ============ 核心修改：健康检查循环 ============
    def health_check_loop(self):
        last_reconnect_time = 0
        while not self._stop_event.is_set():
            time.sleep(self.health_check_interval)
            if not self.status["connected"]:
                self.health_fail_count = 0
                # 未连接时自动重连，每30秒尝试一次
                now = time.time()
                if now - last_reconnect_time > 30:
                    self.log("检测到未连接，尝试自动重连...")
                    success, msg = self.auto_connect_next()      # 统一走优先节点优先逻辑
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

            # 已连接时的健康检查逻辑
            if self._is_tunnel_alive():
                self.health_fail_count = 0
                self._reconnect_fail_count = 0
            else:
                self.health_fail_count += 1
                self.log(f"健康检测失败 (连续 {self.health_fail_count} 次)")

            if self.health_fail_count >= self.max_health_fails:
                self.log(f"连续 {self.health_fail_count} 次健康检测失败，准备切换节点")
                self._switch_to_next_available()      # 内部也改为调用 auto_connect_next
                self.health_fail_count = 0

    def background_check_nodes(self):
        while not self._stop_event.is_set():
            time.sleep(60)
            if self._stop_event.is_set():
                break
            nodes = self.filter_nodes(self.config["region"])
            self.log("开始后台节点检测...")
            available = []
            check_limit = self.config.get("check_limit", 20)
            for node in nodes[:check_limit]:
                if self._stop_event.is_set():
                    break
                if self.status["connected"] and node["ip"] == self.status["node_info"].get("ip"):
                    continue
                if self.test_node(node):
                    available.append(node)
            self._available_nodes = available
            self.log(f"当前可用预备节点: {len(available)} 个")

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

    # ============ 核心修改：切换节点时也走统一逻辑 ============
    def _switch_to_next_available(self):
        self.log("准备切换节点...")
        success, msg = self.auto_connect_next()
        if success:
            self.log(f"切换成功: {msg}")
        else:
            self.log(f"切换失败: {msg}")

    # ============ 核心修改：自动连接下一个节点（优先节点优先） ============
    def auto_connect_next(self):
        """
        自动连接下一个可用节点。
        策略：
        1. 如果设置了优先节点，始终优先从它们之中选择（跳过当前IP）。
        2. 若所有优先节点均不可用（连接失败或已在黑名单），则降级到普通节点列表。
        3. 普通节点列表根据地区、子网优先等设置筛选。
        """
        # 获取当前连接（或最后尝试）的IP
        last_ip = None
        if self.current_node and self.current_node.get("ip"):
            last_ip = self.current_node["ip"]
        elif self.status["node_info"].get("ip"):
            last_ip = self.status["node_info"]["ip"]

        # ---------- 优先节点循环 ----------
        if self.preferred_nodes:
            self.log("正在尝试优先节点...")
            start_idx = 0
            if last_ip:
                for i, node in enumerate(self.preferred_nodes):
                    if node["ip"] == last_ip:
                        start_idx = i + 1
                        break

            # 第一轮：尝试所有非当前IP且不在黑名单的优先节点
            for i in range(len(self.preferred_nodes)):
                if self._stop_event.is_set():
                    break
                idx = (start_idx + i) % len(self.preferred_nodes)
                node = self.preferred_nodes[idx]
                if node["ip"] == last_ip:
                    continue
                if node["ip"] in self._failed_ips:
                    continue
                self.log(f"尝试优先节点: {node['hostname']} ({node['ip']})")
                self._failed_ips.add(node["ip"])
                if self.connect_node(node):
                    return True, node["hostname"]

            # 如果第一轮全部因为黑名单或失败而跳过，尝试临时清空黑名单再试一次（给优先节点第二次机会）
            self.log("优先节点全部跳过或失败，临时清空黑名单再尝试一次...")
            self._failed_ips.clear()
            for i in range(len(self.preferred_nodes)):
                if self._stop_event.is_set():
                    break
                idx = (start_idx + i) % len(self.preferred_nodes)
                node = self.preferred_nodes[idx]
                if node["ip"] == last_ip:
                    continue
                self.log(f"再次尝试优先节点: {node['hostname']} ({node['ip']})")
                if self.connect_node(node):
                    return True, node["hostname"]

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
                if node["ip"] == last_ip:
                    start_index = i + 1
                    break

        prefer_same_subnet = self.config.get("prefer_same_subnet", False)
        subnet_prefix = self.config.get("subnet_prefix_length", 24)

        # 收集候选节点（不在黑名单中且不是当前IP）
        candidates = []
        for i in range(len(nodes)):
            idx = (start_index + i) % len(nodes)
            node = nodes[idx]
            if node["ip"] == last_ip:
                continue
            if node["ip"] in self._failed_ips:
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
                node_sub = self._get_subnet(node["ip"], subnet_prefix)
                if node_sub and last_sub and node_sub == last_sub:
                    subnet_nodes.append(node)
                else:
                    other_nodes.append(node)
            candidates = subnet_nodes + other_nodes

        for node in candidates:
            if self._stop_event.is_set():
                break
            self._failed_ips.add(node["ip"])
            self.log(f"自动连接尝试节点: {node['hostname']} ({node['ip']})")
            if self.connect_node(node):
                return True, node["hostname"]
            self.log(f"节点 {node['hostname']} 连接失败")

        self.log("自动连接失败：所有候选节点均连接失败")
        return False, "所有候选节点均连接失败"

    def start(self):
        self._stop_event.clear()
        self._auto_update_trigger.clear()
        self._failed_ips.clear()
        self.fetch_nodes()

        # 首次启动：优先尝试优先节点
        connected = False
        if self.preferred_nodes:
            self.log("首次启动，尝试优先节点...")
            for node in self.preferred_nodes:
                if self._stop_event.is_set():
                    break
                self._failed_ips.add(node["ip"])
                if self.connect_node(node):
                    connected = True
                    break
                self.log(f"优先节点 {node['hostname']} 连接失败")

        if not connected:
            # 优先节点都失败，尝试普通节点
            nodes = self.filter_nodes(self.config["region"])
            for node in nodes:
                if self._stop_event.is_set():
                    break
                if self.connect_node(node):
                    connected = True
                    break
                self.log(f"节点 {node['hostname']} 连接失败，尝试下一个...")
                time.sleep(1)

        if not connected:
            self.log("所有节点均连接失败，请检查网络或更换地区")
        else:
            self.log("VPN 连接成功建立")

        self._health_thread = threading.Thread(target=self.health_check_loop, daemon=True)
        self._health_thread.start()
        self._bg_check_thread = threading.Thread(target=self.background_check_nodes, daemon=True)
        self._bg_check_thread.start()
        self._auto_update_thread = threading.Thread(target=self._auto_update_loop, daemon=True)
        self._auto_update_thread.start()
        self._history_clean_thread = threading.Thread(target=self._history_clean_loop, daemon=True)
        self._history_clean_thread.start()

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
        if self._history_clean_thread and self._history_clean_thread.is_alive():
            self._history_clean_thread.join(timeout=2)
