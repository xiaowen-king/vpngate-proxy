import json
import os
import secrets
import tempfile

CONFIG_PATH = "/data/config.json"

DEFAULT_CONFIG = {
    "web_password": "admin",
    "api_url": "",
    "socks_port": 1080,
    "web_port": 8080,
    "vpn_user": "",
    "vpn_pass": "",
    "region": "all",
    "node_limit": 200,
    "check_limit": 20,
    "secret_key": "",
    "auto_update_interval": 0,
    "health_fail_threshold": 3,
    "health_check_interval": 10,
    "log_retention_days": 3,
    "health_check_urls": "",
    "latency_check_target": "",
    "speedtest_url": "http://cachefly.cachefly.net/1mb.test",
    "speedtest_retry": 3,
    "prefer_same_subnet": False,
    "subnet_prefix_length": 24,
    "health_check_timeout": 8,
    "preferred_nodes": [],
    "connection_history_retention_days": 30,
    "socks_max_connections": 200,
    "reconnect_interval": 30
}

# 不应通过 API 返回给前端的敏感字段
SENSITIVE_KEYS = {"web_password", "vpn_pass", "secret_key"}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = DEFAULT_CONFIG.copy()
        cfg["secret_key"] = secrets.token_hex(24)
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_hex(24)
        save_config(cfg)
    return cfg


def save_config(cfg):
    """原子写入：先写临时文件再 rename，防止写入中途崩溃导致配置损坏"""
    dir_name = os.path.dirname(CONFIG_PATH) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, CONFIG_PATH)  # 原子替换
    except Exception:
        # 清理临时文件
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def get_safe_config(cfg=None):
    """返回脱敏后的配置（隐藏密码和密钥）"""
    if cfg is None:
        cfg = load_config()
    safe = {}
    for k, v in cfg.items():
        if k in SENSITIVE_KEYS:
            safe[k] = "******" if v else ""
        else:
            safe[k] = v
    return safe
