#!/usr/bin/env bash
# 多节点代理池: 支持订阅链接或单个节点链接, 逐节点测活, 自动故障转移
# 约定(与续期脚本 app.py 对齐):
#   成功 -> IS_PROXY=true  + PROXY_SERVER=socks5://127.0.0.1:1080 写入 GITHUB_ENV
#   失败 -> IS_PROXY=false 写入 GITHUB_ENV, exit 1 (workflow 里 continue-on-error)
set -uo pipefail
export LC_ALL=C

ENV_FILE="${GITHUB_ENV:-}"
NODE_SRC="${NODE_LINK:-}"
PROXY_ADDR="socks5://127.0.0.1:1080"
PROXY_TEST_URL="${PROXY_TEST_URL:-https://api.ipify.org}"

log() { echo "[pool] $*"; }
die() { echo "[pool][ERROR] $*" >&2; [ -n "$ENV_FILE" ] && echo "IS_PROXY=false" >> "$ENV_FILE"; exit 1; }

[ -z "$NODE_SRC" ] && { log "NODE_LINK 未配置, 将直连"; [ -n "$ENV_FILE" ] && echo "IS_PROXY=false" >> "$ENV_FILE"; exit 1; }

# ---------- 收集节点链接 ----------
LINKS_FILE="$(mktemp)"
if [[ "$NODE_SRC" =~ ^https?:// ]]; then
  log "订阅模式: 拉取订阅..."
  raw="$(curl -sL --max-time 40 -A 'v2rayN/6.31' "$NODE_SRC" || true)"
  [ -z "$raw" ] && die "订阅拉取为空(链接失效或需要 token)"
  decoded="$(printf '%s' "$raw" | base64 -d 2>/dev/null || true)"
  printf '%s' "$decoded" | grep -qE '^(vless|vmess|trojan|ss)://' || decoded="$raw"
  printf '%s' "$decoded" | grep -qE '^[[:space:]]*proxies:' && die "这是 Clash/YAML 订阅, 仅支持 v2ray 格式(base64 或明文节点列表)"
  printf '%s\n' "$decoded" | tr -d '\r' | grep -oE '(vless|vmess|trojan|ss)://[^[:space:]]+' | sort -u > "$LINKS_FILE"
  log "订阅解析出 $(wc -l < "$LINKS_FILE" | tr -d ' ') 个节点"
else
  printf '%s\n' "$NODE_SRC" > "$LINKS_FILE"
  log "单节点模式"
fi
[ -s "$LINKS_FILE" ] || die "没有可用节点"
while read -r _l; do echo "::add-mask::$_l"; done < "$LINKS_FILE"

# ---------- 生成 sing-box 配置池 ----------
mkdir -p pool
python3 gen_proxy_configs.py pool < "$LINKS_FILE" > pool/nodes.list || die "节点全部解析失败"
TOTAL=$(wc -l < pool/nodes.list | tr -d ' ')
log "生成 $TOTAL 个节点配置(住宅/家宽关键词优先)"

# ---------- 下载 sing-box ----------
if [ ! -x ./sing-box ]; then
  log "获取 sing-box 最新稳定版..."
  ver="$(curl -s --max-time 20 'https://api.github.com/repos/SagerNet/sing-box/releases' \
    | jq -r '[.[] | select(.prerelease==false)][0].tag_name | sub("^v"; "")')"
  ver="${ver:-1.14.4}"
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) arch="amd64" ;;
  esac
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"
  curl -sL --max-time 120 "$url" | tar xz
  mv "sing-box-${ver}-linux-${arch}/sing-box" ./sing-box
  chmod +x ./sing-box
fi
./sing-box version | head -n1 || die "sing-box 不可用"

# ---------- 逐节点测活 ----------
i=0
while [ $i -lt "$TOTAL" ]; do
  name="$(sed -n "$((i+1))p" pool/nodes.list | cut -d' ' -f2-)"
  cfg="pool/config.${i}.json"
  ./sing-box check -c "$cfg" >/dev/null 2>&1 || { log "[$((i+1))/$TOTAL] '$name' 配置无效, 跳过"; i=$((i+1)); continue; }
  ./sing-box run -c "$cfg" > pool/singbox.log 2>&1 &
  SB_PID=$!
  ok=0
  for t in 1 2 3; do
    sleep 2
    code="$(curl -x "$PROXY_ADDR" -s --max-time 12 -o /dev/null -w '%{http_code}' "$PROXY_TEST_URL" || true)"
    if [ "$code" = "200" ]; then ok=1; break; fi
  done
  if [ "$ok" = "1" ]; then
    ip="$(curl -x "$PROXY_ADDR" -s --max-time 12 'https://api.ipify.org' || true)"
    log "✅ 节点 [$((i+1))/$TOTAL] '$name' 可用, 出口IP: ${ip:-未知}"
    [ -n "$ENV_FILE" ] && { echo "IS_PROXY=true" >> "$ENV_FILE"; echo "PROXY_SERVER=$PROXY_ADDR" >> "$ENV_FILE"; }
    rm -f "$LINKS_FILE"
    exit 0
  fi
  log "❌ 节点 [$((i+1))/$TOTAL] '$name' 不可用, 换下一个"
  kill "$SB_PID" 2>/dev/null || true
  wait "$SB_PID" 2>/dev/null || true
  tail -n 3 pool/singbox.log | sed 's/^/    /' || true
  i=$((i+1))
done

log "全部 $TOTAL 个节点都不可用"
[ -n "$ENV_FILE" ] && echo "IS_PROXY=false" >> "$ENV_FILE"
rm -f "$LINKS_FILE"
exit 1
