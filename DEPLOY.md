# PKI 系统 - 部署启动说明

> 本文档面向内部测试人员，说明如何完成环境配置并启动 PKI 管理系统。

---

## 目录

- [1. 环境要求](#1-环境要求)
- [2. 获取代码](#2-获取代码)
- [3. 安装依赖](#3-安装依赖)
- [4. 获取内部访问证书](#4-获取内部访问证书)
- [5. 配置环境变量](#5-配置环境变量)
- [6. 启动服务](#6-启动服务)
- [7. 访问系统](#7-访问系统)
- [8. 常见问题](#8-常见问题)
- [附录：文件结构说明](#附录文件结构说明)
- [附录：证书更新流程](#附录证书更新流程)

---

## 1. 环境要求

| 组件 | 最低要求 |
|------|---------|
| 操作系统 | Windows 10/11、Linux、macOS |
| Python | 3.9 或更高版本 |
| 内存 | 512 MB |
| 磁盘 | 100 MB 可用空间 |

## 2. 获取代码

```bash
git clone https://github.com/neutrino843/PKI-system.git
cd PKI-system
```

## 3. 安装依赖

```bash
pip install -r requirements.txt
```

安装完成后验证：

```bash
python -c "
from cryptography import x509; print('cryptography OK')
from flask import Flask; print('flask OK')
import ntplib; print('ntplib OK')
"
```

## 4. 获取内部访问证书

本系统配置了启动证书校验机制，启动时需验证内部访问证书（`access_cert.pem`）。

### 方式一：从管理员处获取

将从管理员处收到的 `access_cert.pem` 文件放入以下目录：

```
pki_demo/certs/access_cert.pem
```

### 方式二：自行生成（需管理员权限）

如果拥有项目中间CA私钥，可自行生成：

```bash
# Windows PowerShell
$env:PKI_CA_KEY_PASSWORD="your_ca_password"
python scripts/gen_internal_access_cert.py

# Linux/macOS
export PKI_CA_KEY_PASSWORD="your_ca_password"
python scripts/gen_internal_access_cert.py
```

生成的访问证书路径：

| 文件 | 路径 | 说明 |
|------|------|------|
| `access_cert.pem` | `pki_demo/certs/access_cert.pem` | 访问证书，分发给测试人员 |
| `access_private.pem` | `pki_demo/keys/access_private.pem` | 私钥，仅管理员保留 |

### 证书文件位置示意图

```
PKI-system/
├── pki_demo/
│   ├── certs/
│   │   ├── root_ca_cert.pem        # 根CA证书（已有）
│   │   ├── inter_ca_cert.pem       # 中间CA证书（已有）
│   │   └── access_cert.pem         # 内部访问证书（需放置）
│   └── keys/
│       └── access_private.pem      # 私钥（管理员保管）
```

## 5. 配置环境变量

系统所有密码通过环境变量传入，必须设置以下变量：

### Windows PowerShell

```powershell
$env:PKI_FLASK_SECRET = "your_random_secret_here"
$env:PKI_CA_KEY_PASSWORD = "your_ca_password"
$env:PKI_USER_KEY_PASSWORD = "your_user_password"
$env:PKI_CRL_HMAC_KEY = "your_crl_hmac_key_32bytes"
$env:PKI_AUDIT_HMAC_KEY = "your_audit_hmac_key_32bytes"
$env:PKI_P12_EXPORT_PASSWORD = "your_p12_export_password"
```

### Windows 命令提示符

```batch
set PKI_FLASK_SECRET=your_random_secret_here
set PKI_CA_KEY_PASSWORD=your_ca_password
set PKI_USER_KEY_PASSWORD=your_user_password
set PKI_CRL_HMAC_KEY=your_crl_hmac_key_32bytes
set PKI_AUDIT_HMAC_KEY=your_audit_hmac_key_32bytes
set PKI_P12_EXPORT_PASSWORD=your_p12_export_password
```

### Linux/macOS

```bash
export PKI_FLASK_SECRET="your_random_secret_here"
export PKI_CA_KEY_PASSWORD="your_ca_password"
export PKI_USER_KEY_PASSWORD="your_user_password"
export PKI_CRL_HMAC_KEY="your_crl_hmac_key_32bytes"
export PKI_AUDIT_HMAC_KEY="your_audit_hmac_key_32bytes"
export PKI_P12_EXPORT_PASSWORD="your_p12_export_password"
```

> **密码生成建议**：使用 `python -c "import secrets; print(secrets.token_hex(16))"` 生成随机密钥。

## 6. 启动服务

### 方式一：一键启动（推荐）

```bash
python start_dev.py
```

脚本会自动完成：
1. 检查 Python 版本
2. 检查依赖是否安装
3. 验证内部访问证书
4. 初始化数据库
5. 启动 Flask 服务

可选参数：

| 参数 | 说明 |
|------|------|
| `--install` | 安装依赖后启动 |
| `--gen-cert` | 生成内部访问证书后启动 |
| `--init` | 完整初始化（CA + 证书 + 启动） |
| `--skip-check` | 跳过证书校验（仅开发调试） |
| `--no-server` | 仅执行前置操作，不启动服务 |

示例：

```bash
# 首次使用：安装依赖 + 生成证书 + 启动
python start_dev.py --install --gen-cert

# 跳过证书校验（调试用）
python start_dev.py --skip-check
```

### 方式二：手动启动

```bash
# 初始化 CA（首次使用）
python scripts/setup_pki_full.py

# 生成内部访问证书
python scripts/gen_internal_access_cert.py

# 启动服务
python api_server.py
```

### 启动成功标志

服务启动后终端显示如下信息：

```
============================================================
  PKI System - Internal Access Certificate Check
============================================================

[PASS] Access certificate verification successful
   Serial: 677111235265880714863435537757558087751519892198
   Expires: 2027-06-17 07:17:10+00:00
   System startup authorized.

  [PASS] Access authorized, starting service...
============================================================
[PKI API Server] 启动中...
[PKI API Server] http://localhost:8080
[PKI API Server] 前端界面: http://localhost:8080/
 * Serving Flask app 'api_server'
 * Running on http://127.0.0.1:8080
```

## 7. 访问系统

打开浏览器访问 **[http://localhost:8080](http://localhost:8080)**

### 预置演示账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin123` | CA管理员（全部权限） |
| `ra_zhang` | `ra123456` | RA操作员（证书审核） |
| `auditor_li` | `audit123` | 审计员 |
| `user_wang` | `user1234` | 终端用户 |

> 生产环境部署后请立即修改默认密码。

## 8. 常见问题

### Q1: 启动提示 "Access certificate not found"

**原因**：未检测到内部访问证书。

**解决**：
- 从管理员处获取 `access_cert.pem` 放入 `pki_demo/certs/` 目录
- 或使用管理员权限运行 `python scripts/gen_internal_access_cert.py`
- 开发调试可跳过校验：`python start_dev.py --skip-check`

### Q2: 启动提示 "Certificate has expired"

**原因**：访问证书超过有效期（默认签发 365 天）。

**解决**：联系管理员重新签发证书。

### Q3: 启动提示 "ModuleNotFoundError"

**原因**：Python 依赖未安装。

**解决**：
```bash
pip install -r requirements.txt
```

### Q4: 数据库初始化失败

**原因**：权限不足或旧数据文件冲突。

**解决**：
```bash
# 删除旧数据后重试
del pki_demo\data\*.db
python start_dev.py
```

### Q5: 前端页面加载但接口返回 401

**原因**：登录会话已过期。

**解决**：重新登录系统。

---

## 附录：文件结构说明

```
PKI-system/
├── requirements.txt              # 锁定版本依赖（pip install -r）
├── start_dev.py                  # 一键启动脚本
├── start_pki.bat                 # Windows 快捷启动（需配置密码）
├── api_server.py                 # Flask 后端服务（启动入口）
├── pki_demo/
│   ├── __init__.py               # Python 包标记
│   ├── config.py                 # 系统配置
│   ├── database.py               # 数据库模块
│   ├── auth.py                   # 用户认证与权限
│   ├── access_control.py         # 内部访问证书校验（新增）
│   ├── ra.py                     # RA 注册中心
│   ├── tsa.py                    # 时间戳服务
│   ├── certs/
│   │   ├── root_ca_cert.pem      # 根CA证书
│   │   ├── inter_ca_cert.pem     # 中间CA证书
│   │   └── access_cert.pem       # 内部访问证书（需放置）
│   └── keys/
│       └── access_private.pem    # 访问证书私钥（管理员保管）
├── scripts/
│   ├── gen_internal_access_cert.py  # 内部证书生成工具（新增）
│   ├── setup_pki_full.py            # CA 初始化脚本
│   └── ...
├── pki_ui/                       # 前端界面
└── DEPLOY.md                     # 本文档
```

## 附录：证书更新流程

1. 管理员使用中间CA重新签发：
   ```bash
   python scripts/gen_internal_access_cert.py
   ```
2. 将新的 `access_cert.pem` 分发给所有内部测试人员
3. 测试人员将新证书覆盖到 `pki_demo/certs/access_cert.pem`
4. 重启服务即可生效：
   ```bash
   python start_dev.py
   ```
