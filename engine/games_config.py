"""平台游戏元数据：可热更新的外部配置。

为什么单独抽出来：
    米游社 / 库街区都会上线新游戏，act_id、gameId 会变。把这张表挪到
    config/games.json 后，发现新游戏只要改 JSON，不用动代码、不用重装。

加载顺序：
    1. 内置默认表（下面 DEFAULT_*）
    2. config/games.json 若存在则逐键合并覆盖（允许只写增量）

JSON 结构：
    {
      "mihoyo": {
        "hk4e_cn": {"key": "genshin", "name": "原神",
                    "act_id": "e202311201442471", "signgame": "hk4e",
                    "api": "https://api-takumi.mihoyo.com", "path": "/event/luna"}
      },
      "kuro": {"2": "战双帕弥什", "3": "鸣潮"}
    }
"""

from __future__ import annotations

import json
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.environ.get("CHECKIN_GAMES_CONFIG") or os.path.join(
    _ROOT, "config", "games.json"
)

WEB_API = "https://api-takumi.mihoyo.com"
ZZZ_API = "https://act-nap-api.mihoyo.com"

DEFAULT_MIHOYO = {
    "hk4e_cn": {
        "key": "genshin", "name": "原神",
        "act_id": "e202311201442471", "signgame": "hk4e",
        "api": WEB_API, "path": "/event/luna",
    },
    "hkrpg_cn": {
        "key": "starrail", "name": "星穹铁道",
        "act_id": "e202304121516551", "signgame": "hkrpg",
        "api": WEB_API, "path": "/event/luna",
    },
    "nap_cn": {
        "key": "zzz", "name": "绝区零",
        "act_id": "e202406242138391", "signgame": "zzz",
        "api": ZZZ_API, "path": "/event/luna/zzz",
    },
    "bh3_cn": {
        "key": "honkai3rd", "name": "崩坏3",
        "act_id": "e202306201626331", "signgame": "bh3_cn",
        "api": WEB_API, "path": "/event/luna",
    },
}

# 库街区 gameId -> 展示名。gameId 由接口探测得出（findRoleList 返回 code=200 即有效）。
DEFAULT_KURO = {
    "2": "战双帕弥什",
    "3": "鸣潮",
}

# 自动探测范围：库街区 gameId 逐个试，命中即有角色。
KURO_PROBE_RANGE = range(1, 13)


def _load_overrides() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def mihoyo_games() -> dict:
    """米游社 game_biz -> 配置。外部配置按条目合并覆盖。"""
    games = {k: dict(v) for k, v in DEFAULT_MIHOYO.items()}
    for biz, cfg in (_load_overrides().get("mihoyo") or {}).items():
        if isinstance(cfg, dict):
            games.setdefault(biz, {}).update(cfg)
    return games


def kuro_games() -> dict:
    """库街区 gameId -> 展示名。"""
    games = dict(DEFAULT_KURO)
    for gid, name in (_load_overrides().get("kuro") or {}).items():
        if isinstance(name, str):
            games[str(gid)] = name
    return games


def save_games(payload: dict) -> str:
    """把探测结果写回 config/games.json（增量合并）。"""
    current = _load_overrides()
    for section in ("mihoyo", "kuro"):
        if payload.get(section):
            current.setdefault(section, {}).update(payload[section])
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)
    return CONFIG_PATH
