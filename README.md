# PKI 公钥基础设施系统 v2

一个功能完整的公钥基础设施（PKI）系统，提供证书颁发、管理、吊销及 RFC 3161 合规时间戳服务。支持完整的 CA 证书链（根CA 中间CA 终端证书）、四眼原则审核流程、mTLS 双向认证及 Nginx HTTPS 反向代理部署。

---

## 目录

- [核心功能](#核心功能)
- [v2 更新说明](#v2-更新说明)
- [环境依赖](#环境依赖)
- [快速开始](#快速开始)
- [部署安装](#部署安装)
  - [1. 拉取代码](#1-拉取代码)
  - [2. 安装依赖](#2-安装依赖)
  - [3. 配置密码](#3-配置密码)
  - [4. 初始化 CA](#4-初始化-ca)
  - [5. 启动服务](#5-启动服务)
  - [6. Nginx 反向代理（可选）](#6-nginx-反向代理可选)
  - [7. 访问系统](#7-访问系统)
- [使用指南](#使用指南)
  - [登录与用户角色](#登录与用户角色)
  - [证书申请与签发流程](#证书申请与签发流程)
  - [证书导出](#证书导出)
  - [证书吊销与 CRL](#证书吊销与-crl)
  - [审计日志与备份](#审计日志与备份)
  - [时间戳服务（TSA）](#时间戳服务tsa)
  - [mTLS 双向认证](#mtls-双向认证)
- [证书申请全流程指南](#证书申请全流程指南)
  - [证书类型说明](#证书类型说明)
  - [申请材料](#申请材料)
  - [申请流程（四眼原则）](#申请流程四眼原则)
  - [证书部署指南](#证书部署指南)
  - [常见问题与解决方案](#常见问题与解决方案)
- [常见问题排查](#常见问题排查)
- [维护与更新](#维护与更新)

---

## 核心功能

| 功能模块 | 说明 |
|---------|------|
| 根CA管理 | 自签根CA证书，支持RSA 2048/3072/4096位密钥 |
| 中间CA | 由根CA签发的二级CA，用于签发终端证书 |
| 证书申请（CSR） | 在线生成密钥对并提交证书签名请求 |
| 四眼审核流程 | 初审（RA操作员）+ 二审（CA管理员）双重审批 |
| 证书签发 | 支持TLS服务器证书、客户端证书、代码签名证书 |
| 证书吊销 | 支持5种吊销原因，自动生成CRL |
| PKCS#12导出 | 导出含私钥的浏览器可用证书格式 |
| 时间戳服务（TSA） | RFC 3161合规，支持SHA256/SHA384/SHA512/SM3 |
| 业务场景时间戳 | 电子合同签署、代码版本发布、电子档案归档 |
| 审计日志 | 链式哈希完整性校验，不可篡改 |
| 加密备份 | AES-256-GCM加密的数据库与密钥备份 |
| mTLS双向认证 | Nginx客户端证书验证，仅允许持有证书的用户访问 |
| RBAC权限管理 | 4种角色、15种细粒度权限 |
| REST API | 46+ HTTP API端点，前端全链路对接 |

---

## v2 更新说明

### v2.0 新增功能

- RFC 3161 时间戳服务（TSA）：完整的 RFC 3161 合规时间戳签发与验证
- 3 类业务场景：电子合同签署、代码版本发布、电子档案归档时间戳
- mTLS 双向认证：Nginx 客户端证书验证和证书自动登录
- 前端 TSA 管理界面：时间戳请求、验证、查询及场景管理
- 独立数据库模块：重构 database.py，新增 TSA 相关数据表
- 全链路 REST API 对接：前端完全对接真实后端，移除模拟数据
- 46 项 TSA 测试：全部通过，时间戳性能达 69,078 ops/s

### 安全加固

- 所有密码/密钥从环境变量读取，移除代码中的硬编码
- 敏感文件（证书/私钥/CRL/CSR/备份）从版本控制中排除
- 启动脚本使用占位符模板，用户需自行配置
- 文件完整性校验（SHA-256 manifest）
- 审计日志链式哈希验证

---

## 环境依赖

### 系统要求

| 组件 | 要求 |
|------|------|
| 操作系统 | Windows 10/11 / Linux / macOS |
| Python | 3.9+ |
| Nginx | 1.24+（可选，用于 HTTPS 反向代理） |
| 内存 | 512MB 以上 |
| 磁盘 | 100MB 以上（不含证书存储） |

### Python 依赖

```
cryptography>=41.0.0   加密算法与证书操作
flask                   Web 框架
flask-cors              跨域支持
ntplib>=3.4            NTP 时间同步（TSA 必需）
```

---

## 快速开始

```bash
# 1. 拉取代码
git clone https://github.com/neutrino843/PKI-system.git
cd PKI-system
git checkout v2

# 2. 安装依赖
pip install -r pki_demo/requirements.txt

# 3. 设置环境变量
set PKI_FLASK_SECRET=my_secret_key_2024
set PKI_CA_KEY_PASSWORD=my_ca_password
set PKI_USER_KEY_PASSWORD=my_user_password
set PKI_CRL_HMAC_KEY=my_crl_hmac_key
set PKI_AUDIT_HMAC_KEY=my_audit_hmac_key
set PKI_P12_EXPORT_PASSWORD=my_p12_export_pwd

# 4. 初始化CA
python scripts/setup_pki_full.py

# 5. 启动服务
python api_server.py

# 6. 打开浏览器访问 http://localhost:8080
```

---

## 部署安装

### 1. 拉取代码

```bash
git clone https://github.com/neutrino843/PKI-system.git
cd PKI-system
git checkout v2
```

### 2. 安装依赖

```bash
pip install -r pki_demo/requirements.txt

# 验证安装
python -c "from cryptography import x509; print('cryptography OK')"
python -c "from flask import Flask; print('flask OK')"
```

### 3. 配置密码

系统所有密码通过环境变量传入，切勿在代码中硬编码。

**Windows 命令提示符：**

```batch
set PKI_FLASK_SECRET=your_random_secret_here
set PKI_CA_KEY_PASSWORD=your_ca_password
set PKI_USER_KEY_PASSWORD=your_user_password
set PKI_CRL_HMAC_KEY=your_crl_hmac_key
set PKI_AUDIT_HMAC_KEY=your_audit_hmac_key
set PKI_P12_EXPORT_PASSWORD=your_p12_export_password
```

**Windows PowerShell：**

```powershell
$env:PKI_FLASK_SECRET = "your_random_secret_here"
$env:PKI_CA_KEY_PASSWORD = "your_ca_password"
$env:PKI_USER_KEY_PASSWORD = "your_user_password"
$env:PKI_CRL_HMAC_KEY = "your_crl_hmac_key"
$env:PKI_AUDIT_HMAC_KEY = "your_audit_hmac_key"
$env:PKI_P12_EXPORT_PASSWORD = "your_p12_export_password"
```

**Linux/macOS：**

```bash
export PKI_FLASK_SECRET=your_random_secret_here
export PKI_CA_KEY_PASSWORD=your_ca_password
export PKI_USER_KEY_PASSWORD=your_user_password
export PKI_CRL_HMAC_KEY=your_crl_hmac_key
export PKI_AUDIT_HMAC_KEY=your_audit_hmac_key
export PKI_P12_EXPORT_PASSWORD=your_p12_export_password
```

密码设置建议：Flask Secret 至少 32 位随机字符；CA 密钥密码至少 12 位含大小写字母、数字和特殊字符；HMAC 密钥至少 16 位随机字符串。可使用 `python -c "import secrets; print(secrets.token_hex(16))"` 生成。

### 4. 初始化 CA

首次运行需要初始化 CA 证书链：

```bash
python scripts/setup_pki_full.py
```

该脚本执行以下操作：
1. 生成根CA密钥对并创建自签根CA证书（有效期15年）
2. 生成中间CA密钥对并由根CA签发中间CA证书（有效期5年）
3. 使用中间CA为 localhost 签发TLS服务器证书（有效期2年）
4. 证书保存在 pki_demo/certs/ 和 pki_demo/keys/ 目录

### 5. 启动服务

```bash
python api_server.py
```

启动后终端显示：

```
 * Serving Flask app 'api_server'
 * Debug mode: off
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://192.168.x.x:8080
```

Windows 快捷启动：编辑 start_pki.bat 中的密码占位符后，直接双击运行。

### 6. Nginx 反向代理（可选）

如需 HTTPS 访问，配置 Nginx 反向代理。

**步骤 1：安装 Nginx**

从 [nginx.org](https://nginx.org/) 下载并解压到目标目录。

**步骤 2：配置 SSL**

创建 Nginx 配置文件：

```nginx
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     D:/PKI-system/nginx/certs/pki_server_cert.pem;
    ssl_certificate_key D:/PKI-system/nginx/certs/pki_server_key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**步骤 3：启动 Nginx**

```bash
nginx         # 启动
nginx -s reload  # 重载配置
```

### 7. 访问系统

| 访问方式 | 地址 |
|---------|------|
| HTTP 直连 | http://localhost:8080 |
| HTTPS（Nginx） | https://localhost |

首次访问建议：先导入根CA证书到浏览器受信任存储，消除 HTTPS 安全警告。
1. 浏览器访问 http://localhost:8080
2. 登录后进入首页，点击「下载根CA证书」
3. 保存 .crt 文件后双击，安装证书到受信任的根证书颁发机构

---

## 使用指南

### 登录与用户角色

系统预置 4 个演示账号：

| 用户名 | 密码 | 角色 | 权限范围 |
|--------|------|------|---------|
| admin | admin123 | CA管理员 | 全部权限，包括CA管理、证书签发、TSA管理 |
| ra_zhang | ra123456 | RA操作员 | CSR审核、证书查看、时间戳申请 |
| auditor_li | audit123 | 审计员 | 审计日志查看、证书查看、时间戳验证 |
| user_wang | user1234 | 终端用户 | 证书申请、查看自己的证书、时间戳申请 |

生产环境部署请立即修改默认密码，可通过 `/api/auth/register` 注册新用户后提升权限。

**页面导航：**

| 导航项 | 可见角色 | 说明 |
|-------|---------|------|
| 首页 | 全部 | 系统概览统计、根CA下载 |
| 证书管理 | 全部 | 证书列表搜索、申请新证书 |
| RA审核 | ca_admin, ra_operator | CSR四眼审核流程 |
| 吊销管理 | ca_admin, ra_operator | 证书吊销、CRL生成 |
| 审计日志 | ca_admin, auditor | 操作审计追踪 |
| 备份管理 | ca_admin | 创建和查看加密备份 |
| 用户管理 | ca_admin | 用户列表与权限管理 |
| 时间戳服务 | 全部 | TSA状态、时间戳申请/验证、业务场景 |

### 证书申请与签发流程

系统采用四眼原则（Four-Eyes Principle），需要两人分别完成初审和二审后才能签发证书。

**流程概览：**
终端用户提交申请 RA操作员初审 CA管理员二审 系统签发证书

**详细操作步骤：**

步骤 1：终端用户提交申请
1. 以 user_wang 登录
2. 进入「证书管理」页面
3. 点击「申请证书」按钮
4. 填写通用名称（CN）、组织（OU）和证书类型
5. 系统自动生成 RSA 2048 密钥对并提交 CSR

步骤 2：RA操作员初审
1. 以 ra_zhang 登录
2. 进入「RA审核」页面
3. 在「待审核」列表中看到新提交的申请
4. 点击「初审通过」，验证申请人信息无误后确认

步骤 3：CA管理员二审
1. 以 admin 登录
2. 进入「RA审核」页面
3. 在「待二审」列表中看到初审通过的申请
4. 点击「二审通过」完成最终审批

步骤 4：签发证书
1. 以 admin 登录
2. 进入「证书管理」-「已批准申请」
3. 点击「签发」按钮
4. 系统即刻签发 X.509 v3 证书
5. 证书自动出现在「证书管理」列表中

### 证书导出

签发的证书可在「证书管理」页面操作：

| 导出格式 | 用途 | 操作方式 |
|---------|------|---------|
| PEM | Nginx、Apache等服务器配置 | 点击「导出PEM」 |
| CRT | Windows系统双击安装证书 | 点击「导出CRT」 |
| PKCS#12 (.p12) | 浏览器导入（含私钥） | 点击「导出P12」，输入导出密码 |

浏览器导入 P12 证书：
1. 导出 P12 文件后双击打开
2. 选择「当前用户」存储位置
3. 输入导出时设置的密码
4. 选择「个人」证书存储
5. 完成导入，重启浏览器后生效

### 证书吊销与 CRL

**吊销证书：**
1. 以 admin 或 ra_zhang 登录
2. 进入「证书管理」，找到目标证书
3. 点击「吊销」按钮
4. 选择吊销原因：密钥泄露、CA受损、从属关系变更、已被替代、停止运营
5. 填写说明后确认吊销

**生成 CRL：**
1. 进入「吊销管理」页面
2. 点击「生成 CRL」
3. 系统自动生成 PEM 格式的 CRL 文件
4. 可通过「验证 CRL」检查 CRL 数字签名完整性

### 审计日志与备份

审计日志：
- 所有操作（登录、申请、签发、吊销等）均自动记录
- 支持按操作类型和用户筛选
- 每条日志通过 SHA-256 链式哈希连接，可验证完整性
- 点击「验证完整性」检查日志是否被篡改

加密备份：
1. 以 admin 登录
2. 进入「备份管理」
3. 点击「创建备份」
4. 系统使用 AES-256-GCM 加密数据库和密钥文件
5. 备份文件保存在 pki_demo/backups/ 目录
6. 备份列表显示创建时间和文件大小

### 时间戳服务（TSA）

系统提供完整的 RFC 3161 合规时间戳服务，支持 SHA-256、SHA-384、SHA-512 和 SM3（国密）哈希算法。

**TSA 服务状态：**

进入「时间戳服务」页面可查看服务状态、TSA证书状态、NTP时间源状态、当前时间、今日签发数和速率限制。

**申请时间戳的 5 种方式：**

方式 1：通用时间戳申请
1. 进入「时间戳服务」-「申请时间戳」
2. 填写哈希值、哈希算法，可选填 Nonce 和请求者
3. 提交后返回序列号、生成时间、令牌数据

方式 2：验证时间戳
1. 进入「时间戳服务」-「验证时间戳」
2. 填入哈希值、哈希算法和时间戳令牌
3. 系统验证令牌签名、TSA 证书链、哈希值一致性

方式 3：电子合同签署时间戳
1. 进入「时间戳服务」-「合同签署」
2. 填写合同编号、合同摘要、签署方
3. 系统返回带有精确时间戳的签署证明

方式 4：代码版本发布时间戳
1. 进入「时间戳服务」-「代码发布」
2. 填写版本号和代码摘要
3. 用于证明特定版本代码在特定时间点的存在状态

方式 5：电子档案归档时间戳
1. 进入「时间戳服务」-「档案归档」
2. 填写档案编号、档案摘要和保管期限
3. 适用于电子档案的长期保存与法律存证

**业务场景记录查询：**
「时间戳服务」-「场景记录」查看所有已签发的业务场景时间戳，按时间倒序排列。

### mTLS 双向认证

mTLS（Mutual TLS）要求客户端必须出示由系统签发的证书才能访问网站。

**启用 mTLS：**

步骤 1：签发客户端证书
```bash
python scripts/setup_mtls_client.py
```
脚本将生成客户端密钥对，签发客户端证书，导出 PKCS#12 文件到 export/client_admin.p12。

步骤 2：配置 Nginx 开启 mTLS
```nginx
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     D:/PKI-system/nginx/certs/pki_server_cert.pem;
    ssl_certificate_key D:/PKI-system/nginx/certs/pki_server_key.pem;
    ssl_client_certificate D:/PKI-system/nginx/certs/ca_chain_for_nginx.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

步骤 3：浏览器导入客户端证书
找到 export/client_admin.p12，双击导入到「个人」证书存储。

步骤 4：重启 Nginx `nginx -s reload`

**访问 mTLS 站点：**
浏览器访问 https://localhost/，弹窗要求选择客户端证书，选择后验证通过即可访问。

---

## 证书申请全流程指南

### 证书类型说明

| 证书类型 | 用途 | 适用场景 |
|---------|------|---------|
| TLS服务器证书 | HTTPS网站、API服务 | Web服务器、反向代理 |
| TLS客户端证书 | 身份认证、mTLS | 双向认证、VPN接入 |
| 代码签名证书 | 代码/软件签名 | 软件发布、脚本签名 |
| 电子邮件证书 | 邮件加密与签名 | S/MIME邮件 |
| 时间戳证书 | TSA服务 | 时间戳签发 |

### 申请材料

提交证书申请前，准备好以下信息：

| 材料 | 说明 | 示例 |
|-----|------|------|
| 通用名称（CN） | 证书主体的唯一标识 | www.example.com、zhangsan |
| 组织（Organization） | 所属单位或组织名称 | XX科技有限公司 |
| 部门（OU） | 所属部门（可选） | 技术部 |
| 国家代码（C） | 两位ISO国家代码 | CN |
| 证书类型 | 选择使用用途 | TLS服务器证书 / 客户端证书 |
| SAN（可选） | 主题备用名称 | DNS:example.com |

### 申请流程（四眼原则）

```
步骤 1: 提交       步骤 2: 初审       步骤 3: 二审        步骤 4: 签发       步骤 5: 下载
终端用户提交信息    RA操作员审核        CA管理员确认        CA管理员签发        终端用户获取
自动生成密钥对      验证身份材料        检查权限             更新状态            PEM/P12/CRT
提交CSR           备注说明            批准或拒绝           审计记录            浏览器导入
```

### 证书部署指南

**Web 服务器（Nginx）：**
```nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate     /path/to/server_cert.pem;
    ssl_certificate_key /path/to/server_key.pem;
    ssl_trusted_certificate /path/to/ca_chain.pem;
}
```

**Web 服务器（Apache）：**
```apache
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile      /path/to/server_cert.pem
    SSLCertificateKeyFile   /path/to/server_key.pem
    SSLCertificateChainFile /path/to/ca_chain.pem
</VirtualHost>
```

**浏览器导入客户端证书：**
导出 .p12 格式证书，双击后按向导导入，选择「当前用户」和「个人」证书存储。

**Windows 系统信任根CA：**
下载 root_ca_cert.crt，双击安装到「受信任的根证书颁发机构」。

### 常见问题与解决方案

| 问题 | 原因 | 解决 |
|-----|------|------|
| 浏览器提示证书不受信任 | 根CA证书未导入受信任存储 | 下载根CA .crt 文件，安装到受信任的根证书颁发机构 |
| 浏览器提示证书已过期 | 证书超过有效期 | 重新申请并签发新证书 |
| 浏览器提示域名不匹配 | 证书CN/SAN与访问域名不一致 | 申请证书时包含正确的SAN |
| P12导入提示密码错误 | 导出密码输入不正确 | 重新导出P12，注意区分导出密码与CA密码 |
| 证书私钥丢失 | 密钥文件损坏或删除 | 无法恢复，需吊销原证书后重新申请 |
| CSR审核通过但无法签发 | 私钥文件被删除或移动 | 检查 pki_demo/keys/ 目录是否存在对应私钥 |

---

## 常见问题排查

### 部署问题

502 Bad Gateway 错误
原因：Nginx 反向代理的后端 Flask 服务未启动。
解决：先启动 Flask 后端 `python api_server.py`，确认端口 8080 运行后重载 Nginx `nginx -s reload`。

Flask 启动报错 ModuleNotFoundError
原因：未安装 Python 依赖。
解决：运行 `pip install -r pki_demo/requirements.txt`。

CA 初始化失败，提示密钥密码错误
原因：环境变量 PKI_CA_KEY_PASSWORD 未设置或与已有 CA 密码不一致。
解决：确认环境变量设置正确，或删除旧密钥文件后重新初始化 CA。

Windows 上双击 .pem 文件不能安装证书
原因：Windows 不将 .pem 关联到证书管理器。
解决：使用 .crt 格式，在「证书管理」页面点击「导出CRT」下载后双击安装。

### 功能问题

前端页面加载正确但接口返回 401/403
原因：会话已过期或用户权限不足。
解决：重新登录，确认当前用户角色有对应操作权限。

TSA 时间戳签发失败
原因：NTP 时间同步失败或 TSA 证书未初始化。
解决：检查网络连接，在时间戳服务页面点击同步NTP时间，重载 TSA 证书。

时间戳验证失败
原因：哈希值或算法不匹配，令牌损坏。
解决：确认验证时的哈希值与申请时完全一致，算法选择正确。

CRL 生成失败
原因：HMAC 密钥未配置或目录权限问题。
解决：确认设置了 PKI_CRL_HMAC_KEY 环境变量，检查 pki_demo/crl/ 目录可写。

### 网络问题

外部设备无法访问系统
原因：Flask 默认仅绑定 127.0.0.1。
解决：使用 `python api_server.py --host=0.0.0.0` 允许外部访问。

Nginx HTTPS 配置后无法访问
原因：SSL 证书路径错误或配置语法错误。
解决：检查证书文件路径，运行 `nginx -t` 测试配置，查看 error.log。

### 数据库问题

提示数据库锁定
原因：多个进程同时访问 SQLite 数据库。
解决：确保只有一个 Flask 实例运行，删除锁定文件后重启。

所有证书数据丢失
原因：数据库文件被删除或损坏。
解决：从备份管理页面恢复，或重新初始化 CA 并申请新证书。

---

## 维护与更新

### 日常维护

| 频率 | 任务 | 操作 |
|-----|------|------|
| 每日 | 检查服务状态 | 访问系统首页确认各项统计正常 |
| 每周 | 检查证书到期 | 使用首页「即将到期」统计或 API |
| 每月 | 生成 CRL | 进入「吊销管理」- 生成 CRL |
| 每月 | 创建备份 | 进入「备份管理」- 创建备份 |
| 每季度 | 验证审计日志 | 审计日志 - 验证完整性 |
| 每半年 | 检查 TSA 证书 | 查看 TSA 服务状态 |
| 每年 | 更新 CA 证书 | 如 CA 证书即将到期，重新初始化 |

### 更新升级

**v2.x 小版本升级：**
```bash
git pull origin v2
pip install -r pki_demo/requirements.txt --upgrade
python api_server.py
```

**跨版本升级（v1 到 v2）：**
```bash
git fetch origin
git checkout v2
python scripts/setup_pki_full.py
python api_server.py
```

注意：CA 重新初始化后，所有旧证书将失效，需要重新申请和签发。

### 自定义配置

编辑 pki_demo/config.py 可以修改以下参数：

| 配置项 | 默认值 | 说明 |
|-------|--------|------|
| algorithm.signature_algorithm | RSA | 签名算法（RSA/ECC/SM2） |
| algorithm.hash_algorithm | SHA256 | 哈希算法 |
| algorithm.rsa_key_size | 2048 | RSA密钥长度 |
| cert_policy.default_validity_days | 365 | 默认证书有效期（天） |
| cert_policy.ca_validity_years | 10 | CA证书有效期（年） |
| security.session_timeout_minutes | 30 | 会话超时时间（分钟） |
| tsa.rate_limit | 500 | TSA每秒最大请求数 |
| tsa.ntp_sync_interval | 60 | NTP同步间隔（秒） |
| tsa.max_time_drift | 1.0 | 时间偏差容忍度（秒） |

### 安全建议

1. 修改默认密码：系统首次启动后立即修改所有预置账号的密码
2. 定期轮换密钥：CRL_HMAC_KEY 和 AUDIT_HMAC_KEY 每 90 天更换一次
3. 启用 HTTPS：生产环境必须使用 Nginx 反向代理加 HTTPS
4. 防火墙策略：限制对 8080 端口的直接访问，仅允许通过 Nginx 443 端口访问
5. 备份策略：创建自动备份脚本，保留最近 30 天的备份
6. 日志监控：定期检查审计日志，发现异常及时处理
7. 证书吊销：及时吊销不再使用的证书
8. TSA 时间源：确保 NTP 时间源可信，建议使用内网 NTP 服务器
