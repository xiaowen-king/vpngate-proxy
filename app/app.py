import eventlet
eventlet.monkey_patch()
import resource
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
import eventlet.debug
eventlet.debug.hub_prevent_multiple_readers(False)
import os
import time
import threading
import logging
import secrets
import signal
from logging.handlers import TimedRotatingFileHandler
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
from config import load_config, save_config, get_safe_config
from vpn_manager import VpnManager
import subprocess

# ---------- 日志持久化配置 ----------
LOG_DIR = "/data/logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "vpn-proxy.log")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

cfg = load_config()
file_handler = TimedRotatingFileHandler(
    LOG_FILE,
    when="midnight",
    interval=1,
    backupCount=cfg.get("log_retention_days", 3),
    encoding="utf-8"
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(file_handler)

# 控制台输出（便于 docker logs 查看）
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(console_handler)
# ---------------------------------------

app = Flask(__name__)
app.config['SESSION_COOKIE_NAME'] = 'vpngate_proxy_session'

app.secret_key = cfg.get("secret_key") or secrets.token_hex(24)

socketio = SocketIO(app, async_mode="eventlet")

manager = VpnManager()

def push_log(msg):
    socketio.emit("log", {"message": msg})

manager.set_log_callback(push_log)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "未登录"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == load_config()["web_password"]:
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/api/status")
@login_required
def status():
    return jsonify(manager.status)

@app.route("/api/nodes")
@login_required
def nodes():
    region = request.args.get("region", "all")
    try:
        node_list = manager.filter_nodes(region)
        limit = int(manager.config.get("node_limit", 200))
        # 前端不需要 openvpn_config_base64，去除以节省带宽和前端内存
        display_fields = ("hostname", "ip", "score", "ping", "speed",
                          "country_long", "country_short", "num_sessions",
                          "uptime", "total_users", "total_traffic",
                          "log_type", "operator", "message")
        slim_nodes = [{k: n.get(k, "") for k in display_fields} for n in node_list[:limit]]
        return jsonify(slim_nodes)
    except Exception as e:
        manager.log(f"API /api/nodes 异常: {str(e)}")
        return jsonify({"error": f"服务器内部错误: {str(e)}"}), 500

@app.route("/api/connect", methods=["POST"])
@login_required
def connect():
    data = request.json or {}
    ip = data.get("ip")
    # 先在当前节点列表中查找
    for node in manager.nodes:
        if node.get("ip") == ip:
            success = manager.connect_node(node)
            return jsonify({"success": success})
    # 如果当前列表中没有，尝试从优先节点中获取（已保存完整配置）
    for node in manager.preferred_nodes:
        if node.get("ip") == ip:
            success = manager.connect_node(node)
            return jsonify({"success": success})
    return jsonify({"success": False, "error": "节点未找到"})

@app.route("/api/disconnect", methods=["POST"])
@login_required
def disconnect():
    manager.disconnect()
    return jsonify({"success": True})

@app.route("/api/config", methods=["GET", "POST"])
@login_required
def handle_config():
    if request.method == "GET":
        # 返回脱敏配置，不暴露密码和密钥
        return jsonify(get_safe_config())
    else:
        new_cfg = request.json or {}
        # 合并：前端未传的敏感字段保留原值（前端显示的是 ******）
        current = load_config()
        for sensitive_key in ("web_password", "vpn_pass", "secret_key"):
            val = new_cfg.get(sensitive_key, "")
            if not val or val == "******":
                new_cfg[sensitive_key] = current.get(sensitive_key, "")
        manager.set_config(new_cfg)
        restart_needed = False
        if new_cfg.get("socks_port") != current.get("socks_port") or \
           new_cfg.get("web_port") != current.get("web_port"):
            restart_needed = True
        return jsonify({"success": True, "restart_needed": restart_needed})

@app.route("/api/restart", methods=["POST"])
@login_required
def restart():
    try:
        manager.stop()
        # stop() 内部 join 等待线程退出，额外等待确保完全清理
        time.sleep(2)
        new_cfg = load_config()
        manager.set_config(new_cfg)
        threading.Thread(target=manager.start, daemon=True).start()
        return jsonify({"success": True, "message": "正在重启..."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/auto_connect", methods=["POST"])
@login_required
def auto_connect():
    success, msg = manager.auto_connect_next()
    if success:
        return jsonify({"success": True, "node": msg})
    else:
        return jsonify({"success": False, "error": msg})

@app.route("/api/system")
@login_required
def system_info():
    info = {}
    try:
        ver = subprocess.check_output(["openvpn", "--version"], stderr=subprocess.STDOUT, text=True)
        info["openvpn"] = ver.splitlines()[0].strip()
    except Exception:
        info["openvpn"] = "未知"
    try:
        ver = subprocess.check_output(["python", "--version"], stderr=subprocess.STDOUT, text=True)
        info["python"] = ver.strip()
    except Exception:
        info["python"] = "未知"
    try:
        ver = subprocess.check_output(["ip", "-V"], stderr=subprocess.STDOUT, text=True)
        info["iproute2"] = ver.strip()
    except Exception:
        info["iproute2"] = "未知"
    try:
        ver = subprocess.check_output(["curl", "--version"], stderr=subprocess.STDOUT, text=True)
        info["curl"] = ver.splitlines()[0].strip()
    except Exception:
        info["curl"] = "未知"
    # 读取镜像版本
    try:
        with open("/app/version.txt", "r") as f:
            version = f.read().strip()
        info["镜像SHA"] = version
    except Exception:
        info["镜像SHA"] = "未知"
    return jsonify(info)

@app.route("/api/latency")
@login_required
def latency():
    ms = manager.measure_latency()
    return jsonify({"latency_ms": ms if ms > 0 else None})


@app.route("/api/nodes_latency", methods=["POST"])
@login_required
def nodes_latency():
    data = request.get_json() or {}
    ips = data.get("ips", [])
    if not isinstance(ips, list) or len(ips) == 0:
        return jsonify({"error": "需要提供 IP 列表"}), 400
    # 安全上限，避免恶意请求
    ips = ips[:500]
    latencies = manager.measure_nodes_latency(ips)
    return jsonify({"latencies": latencies})


@app.route("/api/speedtest")
@login_required
def speedtest():
    target = manager.config.get("speedtest_url", "http://cachefly.cachefly.net/1mb.test")
    socks_port = manager.config.get("socks_port", 1080)
    max_retries = int(manager.config.get("speedtest_retry", 3))

    for attempt in range(1, max_retries + 1):
        try:
            start = time.time()
            result = subprocess.run(
                ["curl", "-s", "--socks5", f"127.0.0.1:{socks_port}",
                 "--max-time", "60", "-o", "/dev/null", "-w", "%{size_download}", target],
                capture_output=True, text=True, timeout=70
            )
            elapsed = time.time() - start

            if result.returncode == 0:
                size_bytes = int(result.stdout.strip())
                speed_mbps = round((size_bytes * 8) / (elapsed * 1_000_000), 2)
                return jsonify({
                    "speed_mbps": speed_mbps,
                    "elapsed_sec": round(elapsed, 2),
                    "size_bytes": size_bytes
                })

            # 失败则记录日志，继续重试
            error_msg = result.stderr.strip() or f"curl 退出码: {result.returncode}"
            manager.log(f"测速失败 (第{attempt}次，共{max_retries}次): {error_msg}")

        except Exception as e:
            error_msg = str(e)
            manager.log(f"测速异常 (第{attempt}次，共{max_retries}次): {error_msg}")

        # 如果不是最后一次，等待 5 秒再重试
        if attempt < max_retries:
            time.sleep(5)

    # 所有重试均失败
    return jsonify({
        "speed_mbps": None,
        "error": f"经过 {max_retries} 次尝试仍失败"
    })


@app.route("/api/logs")
@login_required
def get_logs():
    """返回最近的日志内容（最多 1000 行），使用高效尾部读取避免内存暴涨"""
    max_lines = 1000
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify([])
        # 高效读取文件末尾，不将整个文件加载到内存
        lines = _read_last_lines(LOG_FILE, max_lines)
        return jsonify(lines)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _read_last_lines(filepath, n):
    """高效读取文件最后 n 行，不将整个文件加载到内存"""
    try:
        with open(filepath, "rb") as f:
            # 从文件末尾往前读取
            f.seek(0, 2)  # 移到文件末尾
            file_size = f.tell()

            if file_size == 0:
                return []

            # 从末尾读取最多 512KB（日志行通常很短，512KB 足够 1000 行）
            read_size = min(file_size, 512 * 1024)
            f.seek(max(0, file_size - read_size))
            data = f.read(read_size)

            text = data.decode("utf-8", errors="replace")
            all_lines = text.splitlines()

            # 如果读取的不是文件开头，第一行可能是不完整的，跳过
            if file_size > read_size and len(all_lines) > 0:
                all_lines = all_lines[1:]

            return [line.strip() for line in all_lines[-n:]]
    except Exception:
        # fallback：常规读取
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [line.strip() for line in lines[-n:]]


@socketio.on("connect")
def handle_connect():
    # 验证 WebSocket 连接的 session 认证
    if not session.get("logged_in"):
        return False  # 拒绝未认证的 WebSocket 连接
    emit("log", {"message": "WebSocket 已连接"})

def run_app():
    port = int(load_config().get("web_port", 8080))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)

# 连接历史 API（支持分页）
@app.route("/api/connection_history")
@login_required
def get_connection_history():
    sort_field = request.args.get("sort", "start_time")
    order = request.args.get("order", "desc")
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(10, int(request.args.get("per_page", 50))))

    history = list(manager.connection_history)
    # 排序前确保字段可比较，None 替换为空字符串或 0
    reverse = (order == "desc")
    if sort_field == "start_time":
        history.sort(key=lambda x: x.get("start_time") or "", reverse=reverse)
    elif sort_field == "duration":
        def duration_key(rec):
            dur = rec.get("duration")
            if not dur:
                return 0
            try:
                parts = list(map(int, dur.split(':')))
                if len(parts) == 3:
                    return parts[0] * 3600 + parts[1] * 60 + parts[2]
                else:
                    return 0
            except Exception:
                return 0
        history.sort(key=duration_key, reverse=reverse)

    total = len(history)
    start = (page - 1) * per_page
    end = start + per_page
    paged = history[start:end]

    return jsonify({
        "records": paged,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    })

@app.route("/api/connection_history/<record_id>", methods=["DELETE"])
@login_required
def delete_connection_history(record_id):
    manager.delete_connection_record(record_id)
    return jsonify({"success": True})

# 优先节点 API
@app.route("/api/preferred_nodes", methods=["GET", "POST"])
@login_required
def handle_preferred_nodes():
    if request.method == "GET":
        # 仅返回 IP 列表供前端显示
        ips = [node.get("ip", "") for node in manager.preferred_nodes]
        return jsonify({"preferred_ips": ips})

    data = request.json or {}
    ip = data.get("ip")
    action = data.get("action")  # "add" 或 "remove"
    if action == "add":
        target_node = None
        # 先从当前节点列表中查找
        for n in manager.nodes:
            if n.get("ip") == ip:
                target_node = n
                break
        # 如果列表中没有，但当前连接的节点IP匹配，则使用当前连接信息
        if not target_node and manager.status.get("connected"):
            current_info = manager.status.get("node_info", {})
            if current_info.get("ip") == ip:
                target_node = current_info
        if not target_node:
            return jsonify({"success": False, "error": "该节点不在当前节点列表中，且不是当前连接节点，无法设置优先连接"})
        if len(manager.preferred_nodes) >= 3:
            return jsonify({"success": False, "error": "最多只能设置3个优先节点"})
        if any(n.get("ip") == ip for n in manager.preferred_nodes):
            return jsonify({"success": True})  # 已存在
        # 确保优先节点保存完整配置（含 base64），供后续重连使用
        config_b64 = target_node.get("openvpn_config_base64") or manager._node_config_cache.get(ip, "")
        if config_b64:
            target_node = dict(target_node)  # copy
            target_node["openvpn_config_base64"] = config_b64
        manager.preferred_nodes.append(target_node)
        manager.config["preferred_nodes"] = manager.preferred_nodes
        save_config(manager.config)
        return jsonify({"success": True})
    elif action == "remove":
        manager.preferred_nodes = [n for n in manager.preferred_nodes if n.get("ip") != ip]
        manager.config["preferred_nodes"] = manager.preferred_nodes
        save_config(manager.config)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "无效操作"})

def graceful_shutdown(signum, frame):
    threading.Thread(target=manager.stop, daemon=True).start()

signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

if __name__ == "__main__":
    threading.Thread(target=manager.start, daemon=True).start()
    run_app()
