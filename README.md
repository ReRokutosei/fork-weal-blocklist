# PBH Blocklist Builder

提供两套 P2P IP 封禁工具，分别用于 PeerBanHelper 订阅和 VPS 防火墙层的 BT/ed2k 流量过滤

## 项目背景

使用 VPS 进行 BT/ed2k 下载时，版权方会部署蜜罐节点用于追踪下载者 IP

若 VPS 恰好与版权追踪服务器处于同一机房，同网段扫描也可能导致被关联

本 fork 仓库提供的 P2P IP 黑名单方案，用于在 PBH 订阅和 VPS 防火墙层封锁已知的蜜罐 IP 及云厂商 ASN，降低被投诉风险

另：P2P 程序的 Web UI 应从 `*` 改为绑定 `127.0.0.1`，因为绑定 `*` 会监听所有网络接口，若服务未设置强密码或存在漏洞，公网恶意扫描器可直接访问 Web UI 并控制下载客户端。绑定 `127.0.0.1` 后仅本地可访问，配合 Cloudflared、Caddy/Nginx 或隧道进行安全访问与转发，将管理端口的访问权限安全地开放给可信设备

## 内存警告

> [!CAUTION]
> 本规则集约 47 万条 CIDR 条目，PBH 会全部加载到内存中，因此**不适用于低内存**设备

---

## pbh-blocklist-builder.sh

### 原理

从三个上游源下载 P2P IP 黑名单，合并去重后输出 CIDR 格式的封禁列表，供 PeerBanHelper 订阅使用。

- [Naunter BT BlockLists](https://github.com/Naunter/BT_BlockLists)
- [mxdpeep p2p-blocklist-creator](https://github.com/mxdpeep/p2p-blocklist-creator)
- [eMule Security IP Filter](http://upd.emule-security.org/ipfilter.zip)

GitHub Actions 在每周一 00:00 UTC 自动执行构建流程，下载源、合并去重、聚合为 CIDR、发布 Release

### 用法 1

在 PBH WebUI 中：

1. 设置 -> 规则 -> 添加规则
2. URL 填入本仓库 Release 中 `wael.txt` 的 raw 链接
3. 点击立即更新

PBH 会自动下载并解析 CIDR 规则，无需本地部署脚本

默认 `-XX:SoftMaxHeapSize=386M` 可能不足，如遇到内存不足警告或 PBH 崩溃，请增加内存分配：

<details>

| 部署方式 | 操作方法 |
|---------|---------|
| Docker | 在 `docker run` 或 compose 中添加环境变量：`-e JAVA_TOOL_OPTIONS="-Xmx2G -XX:SoftMaxHeapSize=1536M"` |
| Portable (.bat) | 编辑 `.bat` 启动文件，将 `-XX:SoftMaxHeapSize=386M` 改为 `-XX:SoftMaxHeapSize=1536M`，追加 `-Xmx2G` |
| systemd (deb包) | 编辑 `/usr/lib/systemd/system/peerbanhelper.service`，在 ExecStart 中修改上述参数，然后 `systemctl daemon-reload && systemctl restart peerbanhelper` |
| 任何方式 | 设置环境变量 `JAVA_TOOL_OPTIONS=-Xmx2G -XX:SoftMaxHeapSize=1536M` 再启动 PBH（JVM 会自动读取） |

建议分配至少 1.5GB 堆内存给 PBH。2GB VPS 在 Docker 中需确保容器内存上限 >= 2G（`--memory=2G`），否则 `MaxRAMPercentage=85%` 会按容器限制计算

</details>

### 用法 2 (不推荐)

其实在 PBH webUI 里添加一条规则，URL 随便填一个地址（http://127.0.0.1:1/wael），PBH 请求失败后会自动回退到本地缓存文件（截止版本 9.3.14
 (d2f53be8) 有效），我们可以利用该特性完成本地部署

但首先需要将本仓库的 `pbh-blocklist-builder.sh` 略作修改，将输出文件路径改为直接写入 PBH 缓存目录（不做示例，请自行修改，PBH 数据目录通常是 jar 同级的 `/data/sub/`）

接着，找到PBH的配置文件，大致如 `/PeerBanHelper/data/config/profile.yml`

（PBH 添加规则的流程是：`添加规则 → HTTP 请求 → 失败 → 异常捕获 → ROLLBACK 删除规则配置`）

（经过尝试，直接在 webUI 添加假地址是不行的，即使缓存文件已存在并被加载，PBH 仍然把整个流程视为失败并回滚删除规则）

因此，我们需要直接编辑 `/PeerBanHelper/data/config/profile.yml`

`nano profile.yml`，在 `rules:` 下面加一段，跟在 all-in-one 后面：

```yml
      wael-p2p:
        enabled: true
        name: wael-p2p
        url: http://127.0.0.1:1/wael
```

效果如下：

```yml
    rules:
      all-in-one:
        enabled: true
        name: all-in-one
        url: https://bcr.pbh-btn.com/combine/all.txt
      wael-p2p:
        enabled: true
        name: wael-p2p
        url: http://127.0.0.1:1/wael
```

最后，重启 PBH `sudo systemctl restart peerbanhelper`

PBH 重启时日志会出现规则 HTTP 失败，这属于预期内，等待自动回退到 data/sub/wael.txt 即可

~~（说这么多，我自己都感觉麻烦了）~~

---

## update_firewall.sh

### 原理

在 VPS 层面通过 iptables/ipset 实现封锁：

- **ASN 黑名单**：通过 RADb whois 拉取云厂商（DigitalOcean、AWS、GCP、Azure、Vultr、Oracle）的路由表，封锁 443 端口入站流量
- **邻居网段封锁**：封锁同机房 /24（IPv4）和 /64（IPv6）段的入站 443 流量，降低同机房机器间的版权追踪风险
- **P2P 黑名单**：聚合上述三个上游源，合并去重后转为 CIDR，通过 ipset 在内核层面封锁。约 47 万条条目仅占用数十 MB 内存

规则持久化到 `/etc/iptables/`，重启不丢失

### 用法

1. 编辑脚本，修改 `NEIGHBOR_V4` 和 `NEIGHBOR_V6` 为机器的实际网段，如果没有IPv6地址可保持 `NEIGHBOR_V6="-"`：
   ```
   NEIGHBOR_V4="203.0.113.0/24"
   NEIGHBOR_V6="2001:db8::/32"
   ```

2. 首次运行：
   ```bash
   chmod +x update_firewall.sh
   sudo ./update_firewall.sh
   ```

3. 添加到 crontab：
   ```bash
   sudo crontab -e
   ```
   添加（每天凌晨 4 点 UTC 执行）：
   ```
   0 4 * * * /path/to/update_firewall.sh > /var/log/update_firewall.log 2>&1
   ```

### 依赖

```bash
apt install -y curl gzip awk python3 ipset iptables iproute2 whois
```

---

## Credits

P2P List 基于 [Best-blocklist](https://github.com/waelisa/Best-blocklist) by Wael Isa ([wael.name](https://www.wael.name))

## License

[MIT LICENSE](LICENSE)
