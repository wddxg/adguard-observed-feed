本仓库生成一个适用于 AdGuard Home 的合并去重订阅。

## 订阅地址

`https://ghproxy.net/https://raw.githubusercontent.com/wddxg/adguard-observed-feed/main/dist/adguard-home.txt`

## 数据

公开规则来源见 `sources.json`。

## 构建

```sh
python -m unittest discover -s tests -v
python build_filter.py
```
