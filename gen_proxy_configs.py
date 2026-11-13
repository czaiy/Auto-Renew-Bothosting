#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 vless/vmess/trojan/ss 节点链接批量生成为 sing-box 配置文件。

输入: stdin, 每行一个节点链接
输出: 每个可解析节点写 <outdir>/config.<i>.json, 并在 stdout 打印 "<i> <名称>"
"""
import sys, os, json, base64, re
from urllib.parse import urlsplit, parse_qs, unquote

MONTH_KEYWORDS = ("home", "resid", "hinet", "dynamic", "家宽", "住宅", "家庭")


def b64d(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def tls_part(q: dict, port: int) -> dict | None:
    sec = (q.get("security") or [""])[0].lower()
    sni = (q.get("sni") or [""])[0]
    if sec in ("tls", "reality") or (not sec and port == 443):
        t = {"enabled": True, "insecure": False}
        if sni:
            t["server_name"] = sni
        fp = (q.get("fp") or [""])[0]
        if fp:
            t["utls"] = {"enabled": True, "fingerprint": fp}
        if sec == "reality":
            t["reality"] = {
                "enabled": True,
                "public_key": (q.get("pbk") or [""])[0],
                "short_id": (q.get("sid") or [""])[0],
            }
        return t
    return None


def transport_part(q: dict) -> dict | None:
    net = (q.get("type") or ["tcp"])[0].lower()
    if net == "ws":
        tr = {"type": "ws", "path": (q.get("path") or ["/"])[0]}
        host = (q.get("host") or [""])[0]
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if net == "grpc":
        tr = {"type": "grpc", "service_name": (q.get("serviceName") or [""])[0]}
        return tr
    return None


def parse_link(link: str):
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    body = link.split("://", 1)[1]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    name = unquote(frag).strip() or f"{scheme}-node"

    if scheme == "vmess":
        try:
            info = json.loads(b64d(body).decode("utf-8", "ignore"))
        except Exception:
            return None
        try:
            port = int(str(info.get("port", "443")))
        except Exception:
            return None
        ob = {
            "type": "vmess", "tag": "proxy", "server": str(info.get("add", "")),
            "server_port": port, "uuid": str(info.get("id", "")),
            "alter_id": int(info.get("aid") or 0), "security": "auto",
        }
        q = {"tls": [str(info.get("tls", "")).lower()], "sni": [str(info.get("sni", ""))],
             "type": [str(info.get("net", "tcp"))], "path": [str(info.get("path", "/"))],
             "host": [str(info.get("host", ""))]}
        t = tls_part(q, port)
        if t:
            ob["tls"] = t
        tr = transport_part(q)
        if tr:
            ob["transport"] = tr
        if not ob["server"] or not ob["uuid"]:
            return None
        ps_name = str(info.get("ps") or "").strip()
        if ps_name:
            name = ps_name
        return name, ob

    us = urlsplit("//" + body, scheme=scheme)
    host = us.hostname or ""
    try:
        port = us.port or (443 if scheme in ("vless", "trojan") else 8388)
    except ValueError:
        return None
    q = parse_qs(us.query)
    if scheme == "vless":
        uuid = unquote(us.username or "")
        if not uuid or not host:
            return None
        ob = {"type": "vless", "tag": "proxy", "server": host, "server_port": port, "uuid": uuid}
        flow = (q.get("flow") or [""])[0]
        if flow:
            ob["flow"] = flow
        t = tls_part(q, port)
        if t:
            ob["tls"] = t
        tr = transport_part(q)
        if tr:
            ob["transport"] = tr
        return name, ob
    if scheme == "trojan":
        pwd = unquote(us.username or "")
        if not pwd or not host:
            return None
        ob = {"type": "trojan", "tag": "proxy", "server": host, "server_port": port, "password": pwd}
        t = tls_part({"security": ["tls"], "sni": [(q.get("sni") or [""])[0]], "fp": (q.get("fp") or [""])[0]}, port)
        if t:
            ob["tls"] = t
        tr = transport_part(q)
        if tr:
            ob["transport"] = tr
        return name, ob
    if scheme == "ss":
        method, password = "", ""
        userinfo = unquote(us.username or "")
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            try:
                raw = b64d(userinfo).decode("utf-8", "ignore")
                if ":" in raw:
                    method, password = raw.split(":", 1)
            except Exception:
                pass
        if not method or not password or not host:
            return None
        ob = {"type": "shadowsocks", "tag": "proxy", "server": host,
              "server_port": port, "method": method, "password": password}
        return name, ob
    return None


def skeleton(outbound: dict) -> dict:
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "socks-in",
                      "listen": "127.0.0.1", "listen_port": 1080}],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    parsed = []
    for line in sys.stdin:
        link = line.strip()
        if not link:
            continue
        result = parse_link(link)
        if not result:
            # 注意: 公开仓库的日志人人可见, 不要打印链接片段(uuid/密码在链接里)
            print("SKIP unparsable node", file=sys.stderr)
            continue
        parsed.append(result)
    # 住宅/家宽关键词排前面
    parsed.sort(key=lambda t: 0 if any(k in t[0].lower() for k in MONTH_KEYWORDS) else 1)
    for i, (name, ob) in enumerate(parsed):
        with open(os.path.join(outdir, f"config.{i}.json"), "w", encoding="utf-8") as f:
            json.dump(skeleton(ob), f, ensure_ascii=False, indent=1)
        print(f"{i} {name}")
    return 0 if parsed else 1


if __name__ == "__main__":
    sys.exit(main())
