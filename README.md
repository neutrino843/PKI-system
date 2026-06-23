# PKI 公钥基础设施系统

一个功能完整的公钥基础设施（PKI）系统，提供证书颁发、管理、吊销、OCSP 在线状态查询、RFC 3161 时间戳（TSA）、ACME 自动证书管理、SCEP/EST 自动注册、LDAP/AD 目录集成等全栈能力。

---

## 功能总览

| 模块 | 说明 |
|------|------|
| **CA 管理** | 根CA + 中间CA 二级证书链，支持 RSA 2048/3072/4096 |
| **国密算法（SM3）** | X.509 证书/CSR/CRL SM3 签名，支持 SM2-with-SM3 和 SM3-with-RSA OID |
| **证书申请（CSR）** | 在线生成密钥对并提交证书签名请求 |
| **四眼审核流程** | RA操作员初审 + CA管理员二审双重审批，二审通过自动签发 |
| **证书吊销** | 5种吊销原因，CRL 生成 + OCSP 实时状态查询 |
| **OCSP 在线状态** | RFC 6960 合规签名响应，实时查询单张/批量证书吊销状态，60秒缓存加速 |
| **PKCS#12 导出** | 导出含私钥的浏览器可用证书格式 |
| **时间戳服务（TSA）** | RFC 3161 合规，支持 SHA256/SHA384/SHA512/SM3 |
| **ACME 自动证书管理** | RFC 8555 兼容，HTTP-01 挑战验证 |
| **SCEP/EST 自动注册** | RFC 8894 / RFC 7030，网络设备自动申领证书 |
| **LDAP/AD 目录集成** | 自动从企业 AD 同步用户，支持 SSO 登录 |
| **审计日志** | 链式哈希完整性校验，不可篡改 |
| **加密备份** | AES-256-GCM 加密的数据库与密钥备份 |
| **REST API** | 79+ HTTP API 端点，前端全链路对接 |
| **RBAC 权限管理** | 4种角色（CA管理员/RA操作员/审计员/终端用户） |
| **证书模板** | 8种预置模板（TLS服务端/客户端/代码签名/SMIME/VPN等） |
| **证书到期告警** | 三级告警（30天/14天/7天），支持 SMTP 邮件和 Webhook |
| **原生 HTTPS** | Flask ssl_context 零配置 HTTPS，无需 Nginx |

---

## 环境要求

| 组件 | 版本 |
|------|------|
| Python | 3.9+ |
| Nginx | 可选（如需反向代理） |
| 内存 | 512MB+ |
| 磁盘 | 100MB+ |

### Python 依赖

```text
cryptography==46.0.5     # 核心密码学库（X.509证书/CSR/CRL）
Flask==3.1.3             # Web 框架
flask-cors==6.0.5        # 跨域支持
gmssl==3.2.2             # 国密SM3/SM2/SM4算法支持
pyasn1==0.6.3            # ASN.1 DER编码（SM3签名OID构建）
ntplib==0.4.0            # NTP时间同步（TSA时间戳服务）
requests==2.32.5         # HTTP客户端（测试/脚本）
ldap3>=2.9.1             # 仅 LDAP/AD 集成需要
```

---

## 快速开始

### 1. 获取代码

```bash
git clone https://github.com/neutrino843/PKI-system.git
cd PKI-system
git checkout v2
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

验证安装：

```bash
python -c "from cryptography import x509; print('cryptography OK')"
python -c "from flask import Flask; print('flask OK')"
```

### 3. 一键启动（推荐）

```bash
# 初始化 CA 证书链 + 启动服务
python start_dev.py --init --skip-check
```

等待终端输出 `Running on http://127.0.0.1:8080` 后，浏览器访问 `http://localhost:8080`。

**首次登录默认账号：**

| 用户名 | 角色 | 密码 |
|--------|------|------|
| `admin` | CA管理员 | `admin123` |
| `ra_zhang` | RA审核员 | `ra123456` |
| `auditor_li` | 审计员 | `audit123` |
| `user_wang` | 普通用户 | `user1234` |

> **⚠️ 安全警告**：以上为开发演示默认密码。生产部署前必须修改！

### 4. 分步手动启动

```bash
# 设置环境变量（Windows PowerShell）
$env:PKI_FLASK_SECRET = "your_secret_key"
$env:PKI_CA_KEY_PASSWORD = "your_ca_password"
$env:PKI_USER_KEY_PASSWORD = "your_user_password"
$env:PKI_CRL_HMAC_KEY = "your_hmac_key"
$env:PKI_AUDIT_HMAC_KEY = "your_audit_hmac_key"
$env:PKI_P12_EXPORT_PASSWORD = "your_p12_password"

# 初始化 CA
python scripts/setup_pki_full.py

# 生成内部访问证书
python scripts/gen_internal_access_cert.py

# 启动服务（HTTP，端口 8080）
python api_server.py
```

### 5. 启动选项

```bash
# 开发模式（跳过证书校验）
python start_dev.py --skip-check

# HTTP 模式（默认 8080）
python start_dev.py

# HTTPS 原生模式（默认 8443，自动生成 SSL 证书）
python start_dev.py --https

# 指定端口
python start_dev.py --port 443
```

---

## 默认用户与角色

系统首次启动时自动创建 4 个演示用户：

| 用户名 | 密码 | 角色 | 权限范围 |
|--------|------|------|----------|
| `admin` | `admin123` | CA管理员 | 全部权限（签发/吊销/管理用户/TSA管理等） |
| `ra_zhang` | `ra123456` | RA审核员 | 审核 CSR、查看所有证书 |
| `auditor_li` | `audit123` | 审计员 | 查看审计日志、查看所有证书 |
| `user_wang` | `user1234` | 终端用户 | 申请证书、查看自己的证书、导出 P12 |

---

## 使用指南

### 登录

打开 `http://localhost:8080`，输入任意一个默认账号和密码登录。

### 证书申请与签发

1. **提交申请**：登录后进入「证书申请」页面，填写 CN、组织等信息提交 CSR
2. **RA 初审**：使用 `ra_zhang` 账号登录，进入「RA审核」页面进行初审
3. **CA 二审**：使用 `admin` 账号登录，进入「RA审核」页面进行二审
4. **下载证书**：审批通过后，进入「我的证书」页面查看和下载已签发的证书

### 证书吊销与 OCSP

1. **吊销证书**：管理员进入「证书吊销管理」页面，选择证书执行吊销
2. **查询 OCSP 状态**：输入证书序列号，实时查询证书状态（good/revoked/unknown）
3. **生成 CRL**：点击「生成CRL」按钮，生成签名 CRL 文件供客户端使用

### 时间戳服务（TSA）

1. 进入「时间戳服务」页面
2. 输入数据的哈希值，选择算法，点击「签发时间戳」
3. 在「验证」页面输入 TST Token 十六进制编码验证时间戳

### ACME 自动证书管理

ACME 服务端已集成在 API 中，ACME 客户端可通过目录 `https://your-server/acme/directory` 使用。

### LDAP/AD 集成

管理员可在 LDAP 配置页面配置 AD 服务器地址、Base DN 等参数，实现用户同步和 SSO 登录。

---

## HTTPS 配置

### 方式 A：Flask 原生 HTTPS（推荐）

```bash
python api_server.py --https
# 或
python start_dev.py --https
```

首次运行自动生成自签名证书到 `pki_demo/certs/flask_ssl_cert.pem`。

### 方式 B：Nginx 反向代理（生产环境）

参考 `DEPLOY.md` 获取详细部署配置。

---

## 项目结构

```
PKI-system/
├── api_server.py              # REST API 主服务器（入口）
├── start_dev.py               # 一键开发启动脚本
├── requirements.txt           # Python 依赖
├── pki_demo/                  # 核心模块
│   ├── auth.py                # 身份认证与 RBAC 权限管理
│   ├── database.py            # SQLite 数据库持久化层
│   ├── config.py              # 配置管理器
│   ├── security_crl.py        # 证书吊销列表（HMAC 完整性保护）
│   ├── security_crypto.py     # 密码学工具函数
│   ├── ra.py                  # RA 四眼审批流程
│   ├── tsa.py                 # RFC 3161 时间戳服务
│   ├── ocsp.py                # RFC 6960 OCSP 响应器
│   ├── acme_server.py         # RFC 8555 ACME 服务器
│   ├── scep_est.py            # SCEP/EST 自动注册协议
│   ├── ldap_auth.py           # LDAP/AD 目录集成
│   ├── cert_template.py       # 证书模板引擎
│   ├── cert_expiry.py         # 证书到期告警
│   ├── audit.py               # 链式哈希审计日志
│   ├── backup.py              # AES-256-GCM 加密备份
│   ├── api_errors.py          # 标准化 API 错误码
│   ├── access_control.py      # 内部访问证书校验
│   ├── inter_ca.py            # 中间 CA
│   └── unit*.py               # PKI 教学模块（独立可运行）
├── pki_ui/                    # Web 前端
│   ├── index.html             # 单页应用入口
│   ├── css/handdrawn.css      # 手绘风格样式
│   └── js/
│       ├── api.js             # API 通信层
│       └── app.js             # UI 交互逻辑
├── scripts/                   # 辅助脚本
│   ├── setup_pki_full.py      # 初始化 CA 证书链
│   ├── gen_flask_ssl_cert.py  # 生成 Flask SSL 证书
│   ├── gen_selfsigned_localhost.py
│   ├── issue_localhost_cert.py
│   ├── setup_tsa_certificate.py
│   ├── deploy_nginx_proxy.ps1 # Nginx 部署脚本
│   ├── setup_mtls_full.py
│   ├── setup_mtls_client.py
│   ├── crl_sync.ps1
│   ├── trust_root_ca.ps1
│   ├── trust_root_ca.sh
│   └── verify_https.py
└── tests/                     # 测试
    ├── test_tsa.py
    └── test_https_scenario.py
```

---

## 环境变量说明

| 变量名 | 说明 | 必需 |
|--------|------|------|
| `PKI_FLASK_SECRET` | Flask session 加密密钥 | 否（有开发默认值） |
| `PKI_CA_KEY_PASSWORD` | CA 私钥保护密码 | **是** |
| `PKI_USER_KEY_PASSWORD` | 用户私钥保护密码 | **是** |
| `PKI_CRL_HMAC_KEY` | CRL 完整性 HMAC 密钥 | 否（有开发默认值） |
| `PKI_AUDIT_HMAC_KEY` | 审计日志 HMAC 密钥 | 否（有开发默认值） |
| `PKI_P12_EXPORT_PASSWORD` | PKCS#12 导出密码 | 否（有开发默认值） |
| `PKI_SKIP_ACCESS_CHECK` | 跳过内部访问证书校验 | 否（开发用） |
| `PKI_USE_HTTPS` | 启用 HTTPS 模式 | 否 |
| `PKI_API_PORT` | API 服务端口 | 否（默认 8080） |

> **开发模式**：未设置环境变量时，系统使用带有 `DEV_ONLY_` 前缀的默认值。生产部署必须设置强密码。

---

## 安全说明

1. **敏感文件**：私钥文件（`pki_demo/keys/`）、证书文件（`pki_demo/certs/`）、数据库（`pki_demo/data/`）、导出文件（`pki_demo/export/`）等均通过 `.gitignore` 排除在版本控制之外
2. **默认密码**：仅适用于本地开发/演示，生产环境必须在首次部署时通过环境变量修改
3. **内部访问证书**：系统启动时会校验 `access_cert.pem`，确保只有授权人员可启动服务

---

## 证书申请全流程

```
用户提交 CSR → RA操作员初审 → CA管理员二审 → 证书自动签发 → 用户下载
               (ra_zhang)      (admin)         (二审通过后自动签发)
```

---

## 常见问题

**Q: 启动时提示"内部访问证书验证失败"？**
A: 首次使用运行 `python start_dev.py --gen-cert` 生成访问证书，或使用 `--skip-check` 跳过校验。

**Q: 如何重置所有数据？**
A: 删除 `pki_demo/data/` 目录和 `pki_demo/certs/`、`pki_demo/keys/` 目录，重新运行初始化脚本。

**Q: 忘记管理员密码？**
A: 删除 `pki_demo/data/pki.db` 数据库文件，重新启动服务将自动创建默认用户。

**Q: HTTPS 模式下浏览器提示不安全？**
A: 自签名证书会触发浏览器安全警告，点击「高级」→「继续前往」即可。如需正式证书，使用 `--https` 配合真实 CA 签发的证书。


---

## 许可证

本项目仅供学习和演示用途。
有帮助的话可以点个star喵，
有其他问题的话请联系neutrino843@qq.com 
关注猫猫谢谢喵！

