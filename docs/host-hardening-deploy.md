# 宿主加固功能 · 端到端部署自测指南

> 场景：**ClawManager 部署在 K8s Pod 中**，**ksec-bridge + KSec 安装在宿主机上**，
> 通过 ClawManager 界面验证主机防护 / 勒索防护 / 入侵检测 / 合规检测四个 tab 的功能。
>
> 目标：**首次端到端跑通约 20 分钟**。

---

## 架构链路

```
Browser ──HTTPS──> ClawManager Nginx :30443 (K8s Pod)
                      │
                      ├── /api/v1/*     → ClawManager Go 后端
                      └── /api/host/*   → http://<node-host-ip>:9101/agent/v1/* （反代）
                                              │
                                              ▼
                                        ksec-bridge :9101 (systemd, 宿主)
                                              │
                                              ├── 读写 /opt/KSec/policy/*.yaml
                                              ├── tail /opt/KSec/log/*.log (SSE)
                                              └── exec /opt/KSec/bin/KSec ...
                                                       │
                                                       ▼
                                                  KSec daemon (KSecMain)
```

---

## 🖥️ Part 1：宿主机（KSec 所在节点）— 5 步

### 1. 在开发机构建 .deb 包

```bash
cd ~/ClawSecurity/KSecureStandard/ksec-bridge
bash packaging/build-deb.sh
# 产物：build/out/ksec-bridge_0.1.0_amd64.deb（~27 MB，内嵌 Node 20 LTS）
```

构建机要求：`dpkg-deb` + `tar` + `xz` + `curl` + `node`。

### 2. 拷到宿主机

```bash
scp build/out/ksec-bridge_0.1.0_amd64.deb <user>@<host>:/tmp/
```

### 3. 装包

```bash
# 在宿主机上
sudo apt install -y /tmp/ksec-bridge_0.1.0_amd64.deb
```

`postinst` 会自动：
- 复制默认配置到 `/etc/ksec-bridge/env`
- `systemctl daemon-reload + enable + start`

### 4. 防火墙放行 Pod 网段 → :9101

```bash
# Pod CIDR 按你集群实际改（kubectl cluster-info dump | grep -E "podSubnet" 可查）
sudo iptables -I INPUT -p tcp --dport 9101 -s 10.244.0.0/16 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9101 -j DROP   # 其他全拒（MVP 无鉴权靠这个）

# 持久化（Ubuntu）
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

### 5. 用 KSec 兼容版 ids.yaml

KSec 出厂 ids.yaml 在某些环境下 Falco 加载会报错。用 KSec 开发员验证过的版本：

```bash
# 仓库里的 ids-template.yaml 就是验证过的版本
sudo cp ~/ClawSecurity/ClawManager/frontend/src/data/ids-template.yaml \
        /opt/KSec/policy/ids.yaml
```

### 校验宿主侧

```bash
systemctl status ksec-bridge          # active (running)
ss -tln | grep 9101                   # 0.0.0.0:9101（必须 0.0.0.0 不能 127.0.0.1）
curl http://127.0.0.1:9101/agent/v1/status
# 期望返回:
#   {"ready":true,"ksecDaemonRunning":true,"policyDirOK":true,"logDirOK":true,"ksecBinOK":true}
```

如果 `ksecDaemonRunning: false` → 先把 KSec 起来：`sudo systemctl restart KSec`。

---

## 📦 Part 2：ClawManager Pod 侧 — 3 步

### 1. 构建前端 + 镜像

```bash
cd ~/ClawSecurity/ClawManager
cd frontend && npm install && npm run build && cd ..
docker build -t <registry>/clawmanager:host-hardening -f Dockerfile .
docker push <registry>/clawmanager:host-hardening
```

### 2. 确认 K8s Deployment 注入了 Downward API

```bash
kubectl -n clawreef-system get deploy clawmanager-app -o yaml | grep -A2 KSEC_BRIDGE
```

期望看到：
```yaml
- name: KSEC_BRIDGE_HOST
  valueFrom:
    fieldRef: { fieldPath: status.hostIP }   # ← Pod 拿到所在宿主机 IP
- name: KSEC_BRIDGE_PORT
  value: "9101"
```

没有的话改 `deployments/k8s/clawmanager.yaml` 加上，然后 `kubectl apply -f`。

### 3. 滚动更新镜像

```bash
kubectl -n clawreef-system set image deployment/clawmanager-app \
  clawmanager=<registry>/clawmanager:host-hardening
kubectl -n clawreef-system rollout status deployment/clawmanager-app
```

### 校验 Pod → 宿主连通

```bash
kubectl -n clawreef-system exec -it deploy/clawmanager-app -- \
  sh -c 'curl -s http://$KSEC_BRIDGE_HOST:$KSEC_BRIDGE_PORT/agent/v1/status'
# 同样期望 {"ready":true,...}
```

如果失败 → 检查 Part 1 第 4 步防火墙、`ss -tln` 是否 0.0.0.0。

---

## 🌐 Part 3：浏览器端到端测试 — 6 项

进入 `https://<clawmanager>/admin/secplane/isolate/host`，按顺序点：

| # | UI 动作 | 宿主机验证 |
|---|---|---|
| 1 | 打开页面 | 4 张 hero 卡有真实数据（加固代理状态 / 24h 告警数）|
| 2 | **主机防护** → 总开关打开 → 保存并应用 | `grep access_control /opt/KSec/conf/KSec.yaml` → `on` |
| 3 | **勒索防护** → 总开关打开 → 保存并应用 | `grep ^ransom /opt/KSec/conf/KSec.yaml` → `on` |
| 4 | **入侵检测** → 总开关打开 → 保存并应用 | `grep intrusion_detection /opt/KSec/conf/KSec.yaml` → `on`<br>`pgrep falco` 有进程 |
| 5 | **合规检测** → 勾全部大类 → 立即检测 | `ls -lt /opt/KSec/compliance/log/scan_*` 有新文件 |
| 6 | 触发告警：宿主上跑 `nc -l 4444` 或 `cat /etc/shadow` | UI 对应日志表 1-2 秒内出现新行 |

---

## 🐞 卡住时先看的日志

### 宿主侧

```bash
sudo journalctl -u ksec-bridge -f --since "5 min ago"
tail -f /opt/KSec/log/intrusion_detection_run.log    # Falco 加载错误
tail -f /opt/KSec/log/KSec.log                       # KSec daemon 错误
```

### Pod 侧

```bash
kubectl -n clawreef-system logs -f deploy/clawmanager-app | grep -E "host|9101|bridge"
kubectl -n clawreef-system exec -it deploy/clawmanager-app -- nginx -T 2>&1 \
  | grep -A6 "ksec_bridge"
# 确认 envsubst 已把 ${KSEC_BRIDGE_HOST} 替换成实际宿主 IP，不是字面量
```

### 浏览器

F12 → Network → 看 `/api/host/*` 的 status code：

| code | 含义 | 排查方向 |
|---|---|---|
| 502 | nginx 上行连不到 9101 | 防火墙 / bridge 没起 / bridge 监听了 127.0.0.1 而不是 0.0.0.0 |
| 503 | bridge 起了但 KSec daemon 没跑 | `systemctl status KSec` |
| 400 | 前端发的 schema 不对 | 看 bridge journalctl 里的 zod 报错 |
| socket hang up | upstream 中途断 | bridge 进程崩了，看 journalctl |

---

## ⏱️ 预计时间

| 步骤 | 时间 |
|---|---|
| 宿主侧 5 步 | 5 分钟（含构建） |
| Pod 侧 3 步 | 8-10 分钟（含 docker push） |
| 浏览器 6 项点击验证 | 5 分钟 |
| **总计首次跑通** | **~20 分钟** |

后续迭代（只改前端）：跳过 Part 1，只跑 Part 2 + 浏览器复测。

---

## 易踩的坑（按出现频率排）

1. **bridge 9101 没监听 0.0.0.0** → Pod 连不到。`ss -tln | grep 9101` 必须是 `0.0.0.0:9101`。检查 `/etc/ksec-bridge/env` 里 `KSEC_BRIDGE_HOST=0.0.0.0`，然后 `sudo systemctl restart ksec-bridge`。
2. **防火墙没放 Pod CIDR** → Pod 那边 timeout / connection refused。
3. **`KSEC_BRIDGE_HOST` Downward API 没注入** → Nginx 启动时 `${KSEC_BRIDGE_HOST}` 没被替换，upstream 解析失败。
4. **ids.yaml 没换到 Falco 兼容版** → Falco 起不来 → 入侵检测显示 502。
5. **bridge 跑非 root** → 写 `/opt/KSec/conf/KSec.yaml` 时 EACCES。deb 包默认 systemd 用 root，正常应该没问题。
6. **`/etc/ksec-bridge/env` 修改后没 restart** → 旧配置仍在生效。改完必 `sudo systemctl restart ksec-bridge`。

---

## 卸载

```bash
sudo apt remove ksec-bridge          # 留 /etc/ksec-bridge/env（升级再装会复用）
sudo apt purge ksec-bridge           # 连配置一起删

# 防火墙规则手动清（apt 不管这个）
sudo iptables -D INPUT -p tcp --dport 9101 -s 10.244.0.0/16 -j ACCEPT 2>/dev/null
sudo iptables -D INPUT -p tcp --dport 9101 -j DROP 2>/dev/null
sudo netfilter-persistent save
```
