# MySecretPVE

简体中文 | English: see README.en.md

一个用于管理 Proxmox VE 集群防火墙 IPSet 的轻量级 Web 应用。基于 Flask + proxmoxer，使用 SQLite（SQLAlchemy）持久化 PVE 与腾讯云凭据等设置。

## 功能概览

- IPSet 管理：新建、删除、重命名、备注编辑、单条添加/移除、批量导入/移除、导出文本
- 登录与会话：简单账户密码登录，`config.py` 中配置
- PVE 连接：支持密码登录或 API Token；可开关 SSL 校验；支持标准端口与自定义端口
- 一键连通性测试：`/api/test/pve`、`/api/test/tencent` 调试接口
- 设置持久化：`settings.db` 自动创建与轻量迁移，无需手动建表
- 可选调试：开启 HTTP 请求详细日志（见下文“调试与日志”）

## 运行环境

- Python 3.10+（使用了 `X | Y` 类型标注语法）
- Proxmox VE 可访问的网络环境

## 安装与启动

1) 安装依赖

```bash
pip install -r requirements.txt
```

2) 调整基础配置（强烈建议修改默认值）

- 编辑 `config.py`：
  - `WEB_USERNAME` / `WEB_PASSWORD`：Web 登录账户与密码（默认 `admin`/`password`）
  - `FLASK_SECRET_KEY`：Flask 会话密钥，用于签名 Cookie
  - `ENABLE_HTTP_DEBUG` / `ENABLE_HTTP_DEBUG_SHOW_SECRETS`：调试开关（也可用环境变量控制）

3) 启动开发服务器

```bash
python main.py
# 访问 http://localhost:5000
```

4) 生产部署（示例）

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 webapp:app
```

## 部署

- Ubuntu + Nginx + systemd 部署：见 `docs/DEPLOYMENT_UBUNTU_NGINX.md`。
- 示例配置：`deploy/mysecretpve.service`、`deploy/nginx/mysecretpve.conf`。

## 使用指南

- 首次登录：使用 `config.py` 中配置的账户密码
- 仪表盘：显示是否已配置 PVE 连接
- IPSet 管理：
  - 列表页：创建/删除 IPSet
  - 详情页：新增/移除 IP 或网段（CIDR），批量导入/批量移除，重命名与备注编辑，导出为 `.txt`
- 设置页面：
  - PVE 设置：`host`、`user`、`password`、`ssl_verify`、`protocol`、`port`、`token_name`/`token_value`
    - Host 可填 `https://host:8006/`、`host:8006`、`[2001:db8::1]:8006` 等，程序会归一化并保存为主机与端口
    - 使用 API Token 时优先于密码认证
  - 腾讯云设置：`secret`、`key`（用于校验凭据有效性，及后续扩展）

## API（调试用）

- `POST /api/test/pve`：测试与 PVE 的连通与鉴权
  - Body（JSON，可只传需覆盖项）：
    ```json
    {
      "host": "https://pve.example.com:8006",
      "user": "root@pam",
      "password": "...",
      "ssl_verify": true,
      "protocol": "https",
      "port": 8006,
      "token_name": "mytoken@pve",
      "token_value": "...",
      "otp": "可选一次性验证码"
    }
    ```
  - 成功时返回检测到的节点数量

- `POST /api/test/tencent`：校验腾讯云凭据是否有效
  - Body（JSON）：`{"secret": "...", "key": "..."}`（若不提供则使用已保存的值）

## 目录结构

```
.
├── main.py               # 入口，仅启动 Flask 应用
├── webapp.py             # Flask 路由、PVE 连接与页面逻辑
├── modules/
│   ├── firewall.py       # 基于 proxmoxer 的防火墙/IPSet 封装
│   ├── settings.py       # SQLAlchemy 模型与 Settings 持久化
│   ├── cloudflare.py     # Cloudflare IP 段获取（后续可接入）
│   ├── tencent.py        # 腾讯云 CDN / 域名操作封装（扩展用）
│   └── ipranger.py       # 获取公网 IPv4/IPv6（扩展/工具）
├── templates/            # Jinja2 模板（登录/仪表盘/IPSet/设置等）
├── requirements.txt      # 依赖列表
├── config.py             # Web 登录、调试开关等配置
└── settings.db           # SQLite 数据库（运行时自动生成）
```

## 调试与日志

- 开启 HTTP 请求与 proxmoxer 详细日志：
  - 环境变量：
    ```bash
    export HTTP_DEBUG=1
    # 如需在日志中显示敏感值（不推荐）：
    export HTTP_DEBUG_SHOW_SECRETS=1
    ```
  - 或直接在 `config.py` 中将 `ENABLE_HTTP_DEBUG` 设为 `True`

## 安全与最佳实践

- 首次部署务必修改默认登录密码与 `FLASK_SECRET_KEY`
- 建议使用 API Token 访问 PVE，并最小化权限
- 生产环境开启 `ssl_verify` 并正确配置 CA 证书
- `settings.db` 中包含敏感信息，请妥善保管并限制访问权限

## 许可

本项目采用 Apache License 2.0 协议，详见 LICENSE。

## 致谢

- proxmoxer、Flask、SQLAlchemy 等开源项目
