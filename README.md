# PBH Blocklist Builder

每周自动构建 P2P IP 封禁规则，输出 **CIDR 格式**，供 [PeerBanHelper](https://github.com/PBH-BTN/PeerBanHelper) 订阅使用。

## 用法

在 PBH WebUI 中：

1. **设置 → 规则 → 添加规则**
2. **URL** 填入本仓库 Release 中 `wael.txt` 的 raw 链接
3. 点击 **立即更新**

PBH 会自动下载并解析 CIDR 规则，无需本地部署脚本。

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
