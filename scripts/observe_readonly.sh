#!/usr/bin/env bash
# 只读观测：不动目标机任何状态（不安装、不卸载、不 pm clear、不 force-stop、不点屏幕、不广播）
# 用法： bash tools/runtime/observe_readonly.sh [SERIAL] [SECONDS]
set -u

ADB="${ADB:-C:/Users/ROG STRIX/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb.exe}"
SERIAL="${1:-}"
SECS="${2:-60}"
PKG="com.alibaba.android.rimet.w2534344268"
OUT="scan/runtime"
mkdir -p "$OUT"

A() { if [ -n "$SERIAL" ]; then "$ADB" -s "$SERIAL" "$@"; else "$ADB" "$@"; fi; }

echo "[0] 设备信息"
A shell 'getprop ro.product.model; getprop ro.product.manufacturer; getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.product.cpu.abi; getprop ro.build.tags' > "$OUT/device.txt" 2>&1
cat "$OUT/device.txt"

echo "[1] 包信息（只读）"
A shell "dumpsys package $PKG" > "$OUT/dumpsys_package.txt" 2>&1
grep -E "versionName|versionCode|firstInstallTime|lastUpdateTime|flags=|pkgFlags|signatures|debuggable" "$OUT/dumpsys_package.txt" | head -20

echo "[2] 路径与 APK 指纹"
A shell "pm path $PKG" > "$OUT/apk_path.txt" 2>&1
cat "$OUT/apk_path.txt"
APKPATH=$(grep -m1 '^package:' "$OUT/apk_path.txt" | sed 's/^package://')
if [ -n "$APKPATH" ]; then
  A pull "$APKPATH" "$OUT/installed_base.apk" >/dev/null 2>&1 && \
    python - "$OUT/installed_base.apk" <<'PY'
import hashlib,sys
p=sys.argv[1]; h=hashlib.sha256()
with open(p,'rb') as f:
    for b in iter(lambda: f.read(1<<22), b''): h.update(b)
print("installed sha256:", h.hexdigest())
print("ours      sha256: 2433588b58436a0e55270f2a66c286f0fe7bc41618d7f5e069fc6ef99d609195")
print("identical:", h.hexdigest()=="2433588b58436a0e55270f2a66c286f0fe7bc41618d7f5e069fc6ef99d609195")
PY
fi

echo "[3] 进程与组件状态"
A shell "ps -A | grep -i rimet" > "$OUT/processes.txt" 2>&1; cat "$OUT/processes.txt"
A shell "dumpsys activity providers | grep -A3 -i rimet" > "$OUT/providers.txt" 2>&1
A shell "dumpsys activity services $PKG" > "$OUT/services.txt" 2>&1

echo "[4] 网络：远端 IP 快照（/proc/net/tcp{,6}，只读）"
A shell "cat /proc/net/tcp; echo ---; cat /proc/net/tcp6" > "$OUT/tcp_raw.txt" 2>&1
python - "$OUT/tcp_raw.txt" "$OUT/remote_ips.txt" <<'PY'
import sys
raw=open(sys.argv[1],encoding='utf8',errors='replace').read().splitlines()
def hex2ip(h):
    if len(h)==8:
        b=[int(h[i:i+2],16) for i in (6,4,2,0)]
        return ".".join(map(str,b))
    return None
ips=set()
for ln in raw:
    p=ln.split()
    if len(p)<4 or p[0]=='sl': continue
    rem=p[2]
    if ':' not in rem: continue
    addr,port=rem.rsplit(':',1)
    ip=hex2ip(addr) if len(addr)==8 else None
    if ip and ip not in ('0.0.0.0','127.0.0.1'):
        ips.add("%s:%d"%(ip,int(port,16)))
open(sys.argv[2],'w',encoding='utf8').write("\n".join(sorted(ips)))
print("remote endpoints:",len(ips))
print("\n".join(sorted(ips)[:40]))
PY

echo "[5] 抓 logcat ${SECS}s（只读；期间请正常使用 App）"
A logcat -c 2>/dev/null
timeout_bin=""
A logcat -v time > "$OUT/logcat_${SECS}s.txt" 2>&1 &
LOGPID=$!
sleep "$SECS"
kill $LOGPID 2>/dev/null
wait $LOGPID 2>/dev/null
wc -l "$OUT/logcat_${SECS}s.txt" 2>/dev/null

echo "[6] 从日志里抽：域名 / 账号组织线索 / 配置键"
python - "$OUT/logcat_${SECS}s.txt" "$OUT/log_extract.md" <<'PY'
import re,sys
txt=open(sys.argv[1],encoding='utf8',errors='replace').read()
hosts=sorted(set(re.findall(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})',txt)))
keys=sorted(set(re.findall(r'\b([a-z][a-z0-9_]{8,}_android)\b',txt)))
corp=sorted(set(re.findall(r'\b(corpId|realm|orgId|orgName|uid|nick)\b\s*[=:]\s*([^\s,;]{1,40})',txt)))
with open(sys.argv[2],'w',encoding='utf8') as f:
    f.write("## hosts\n"+"\n".join(hosts[:200])+"\n\n## gaea keys\n"+"\n".join(keys[:200])+"\n\n## identity-ish\n")
    for a,b in corp[:100]: f.write(f"{a}={b}\n")
print("hosts",len(hosts),"keys",len(keys))
PY

echo "done -> $OUT"
