# PBH Blocklist Builder

每周自动构建 P2P IP 封禁规则，输出 **CIDR 格式**，供 [PeerBanHelper](https://github.com/PBH-BTN/PeerBanHelper) 订阅使用。

## 用法

在 PBH WebUI 中：

1. **设置 → 规则 → 添加规则**
2. **URL** 填入本仓库 Release 中 `wael.txt` 的 raw 链接
3. 点击 **立即更新**

PBH 会自动下载并解析 CIDR 规则，无需本地部署脚本。

## 内存警告

本规则集约 **47 万条 CIDR 条目**，PBH 会全部加载到内存中，因此不适用于低内存设备。默认 `-XX:SoftMaxHeapSize=386M` 可能不足，如遇到内存不足警告或 PBH 崩溃，请增加内存分配：

| 部署方式 | 操作方法 |
|---------|---------|
| **Docker** | 在 `docker run` 或 compose 中添加环境变量：`-e JAVA_TOOL_OPTIONS="-Xmx2G -XX:SoftMaxHeapSize=1536M"` |
| **Portable (.bat)** | 编辑 `.bat` 启动文件，将 `-XX:SoftMaxHeapSize=386M` 改为 `-XX:SoftMaxHeapSize=1536M`，追加 `-Xmx2G` |
| **systemd (deb包)** | 编辑 `/usr/lib/systemd/system/peerbanhelper.service`，在 ExecStart 中修改上述参数，然后 `systemctl daemon-reload && systemctl restart peerbanhelper` |
| **任何方式** | 设置环境变量 `JAVA_TOOL_OPTIONS=-Xmx2G -XX:SoftMaxHeapSize=1536M` 再启动 PBH（JVM 会自动读取） |

建议分配 **至少 1.5GB 堆内存** 给 PBH。2GB VPS 在 Docker 中需确保容器内存上限 ≥ 2G（`--memory=2G`），否则 `MaxRAMPercentage=85%` 会按容器限制计算。

## 数据源

- [Naunter BT BlockLists](https://github.com/Naunter/BT_BlockLists)
- [mxdpeep p2p-blocklist-creator](https://github.com/mxdpeep/p2p-blocklist-creator)
- [eMule Security IP Filter](http://upd.emule-security.org/ipfilter.zip)

## 自动化

GitHub Actions 每周一 00:00 UTC 自动执行：

1. 下载三个上游源
2. 合并去重 → 聚合为 CIDR 条目
3. 发布 Release

也可手动触发 `workflow_dispatch`。

## Credits

基于 [**Best-blocklist**](https://github.com/waelisa/Best-blocklist) by **Wael Isa** ([wael.name](https://www.wael.name))。

## License

MIT — 见 [LICENSE](LICENSE)。
