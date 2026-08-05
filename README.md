# DNS 拦截列表

本仓库生成一个适用于 AdGuard Home 的合并去重订阅。

## 订阅地址

`https://ghproxy.net/https://raw.githubusercontent.com/wddxg/adguard-observed-feed/main/dist/adguard-home.txt`

## 数据

`data/observed-domain-hits.csv` 仅保留域名和累计命中次数，不包含时间、客户端、设备或网络信息。记录按域名倒数第二级标签排序，例如 `xx.xx.xiaomi.com` 按 `xiaomi` 归类。

公开规则来源及许可证见 `sources.json`。

## 构建

```sh
python -m unittest discover -s tests -v
python build_filter.py
```

GitHub Actions 每周自动更新公开来源并重新生成 `dist/adguard-home.txt`；产物没有变化时不会产生提交。
