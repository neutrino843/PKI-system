/**
 * PKI系统 - 手绘风格前端交互逻辑 v1.0
 */

// ============================================================
// 全局状态
// ============================================================
let currentUser = null;

// ============================================================
// UI工具
// ============================================================
const UI = {
    toast(msg, type = 'info') {
        const c = document.getElementById('toastContainer');
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.innerHTML = `<span>${msg}</span>`;
        c.appendChild(el);
        setTimeout(() => { el.classList.add('toast-out'); setTimeout(() => el.remove(), 300); }, 3000);
    },
    showModal(id) { document.getElementById(id).classList.add('show'); },
    hideModal(id) { document.getElementById(id).classList.remove('show'); },
};

// ============================================================
// 路由
// ============================================================
function navigateTo(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById(`page-${page}`);
    if (target) { target.classList.add('active'); window.scrollTo({ top: 0, behavior: 'smooth' }); }
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    const active = document.querySelector(`.menu-item[data-page="${page}"]`);
    if (active) active.classList.add('active');
    closeMenu();
}

function openMenu() {
    document.getElementById('sideMenu').classList.add('open');
    document.getElementById('menuOverlay').classList.add('show');
    document.getElementById('menuBtn').classList.add('active');
}
function closeMenu() {
    document.getElementById('sideMenu').classList.remove('open');
    document.getElementById('menuOverlay').classList.remove('show');
    document.getElementById('menuBtn').classList.remove('active');
}

// ============================================================
// 页面渲染（所有数据来自后端API）
// ============================================================

/* ----- 登录 ----- */
async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    const errorEl = document.getElementById('loginError');

    try {
        const resp = await API.login(username, password);
        currentUser = resp.user;
        errorEl.classList.remove('show');
        document.getElementById('loginPage').style.display = 'none';
        document.getElementById('appContainer').style.display = 'block';
        updateUserInfo();
        navigateTo('home');
        renderHome();
        UI.toast(`欢迎回来，${currentUser.name}`, 'success');
    } catch (err) {
        errorEl.textContent = err.message || '登录失败，请重试';
        errorEl.classList.add('show');
        document.getElementById('loginPassword').value = '';
    }
}

async function handleLogout() {
    try {
        await API.logout();
    } catch (_) {}
    currentUser = null;
    document.getElementById('appContainer').style.display = 'none';
    document.getElementById('loginPage').style.display = 'flex';
    document.getElementById('loginUsername').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('loginError').classList.remove('show');
    UI.toast('已安全退出', 'info');
}

function updateUserInfo() {
    if (currentUser) {
        document.getElementById('userName').textContent = currentUser.name;
        document.getElementById('userRole').textContent = currentUser.roleName;
        document.getElementById('menuUserInfo').textContent = `${currentUser.name} - ${currentUser.roleName}`;
        // 管理菜单：仅admin可见
        const menuUsers = document.getElementById('menuUsers');
        if (menuUsers) {
            menuUsers.style.display = currentUser.role === 'ca_admin' ? 'flex' : 'none';
        }
    }
}

/* ----- 注册 ----- */
function showRegisterForm() {
    document.getElementById('loginCard').style.display = 'none';
    document.getElementById('registerCard').style.display = 'block';
}
function hideRegisterForm() {
    document.getElementById('registerCard').style.display = 'none';
    document.getElementById('loginCard').style.display = 'block';
    document.getElementById('registerError').classList.remove('show');
}

async function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('regUsername').value.trim();
    const name = document.getElementById('regName').value.trim();
    const password = document.getElementById('regPassword').value;
    const password2 = document.getElementById('regPassword2').value;
    const errorEl = document.getElementById('registerError');

    if (password !== password2) {
        errorEl.textContent = '两次密码输入不一致';
        errorEl.classList.add('show');
        return;
    }

    try {
        const resp = await API.register(username, password, name);
        UI.toast('注册成功，请登录', 'success');
        // 自动填充用户名
        document.getElementById('loginUsername').value = username;
        hideRegisterForm();
    } catch (err) {
        errorEl.textContent = err.message || '注册失败';
        errorEl.classList.add('show');
    }
}

/* ----- 首页 ----- */
async function renderHome() {
    try {
        const stats = await API.getStats();
        document.getElementById('statCerts').textContent = stats.totalCerts;
        document.getElementById('statValid').textContent = stats.validCerts;
        document.getElementById('statExpiring').textContent = stats.expiringCerts;
        document.getElementById('statRevoked').textContent = stats.revokedCerts;
    } catch (_) {}
}

/* ----- 证书管理 ----- */
async function renderCertificates() {
    const tbody = document.getElementById('certTableBody');
    const statusFilter = document.getElementById('certStatusFilter').value;
    const search = document.getElementById('certSearch').value.toLowerCase();

    try {
        const certs = await API.getCertificates(statusFilter, search);
        if (certs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><svg viewBox="0 0 80 80" fill="none" stroke="#BFA89C" stroke-width="2"><circle cx="40" cy="40" r="30" stroke-dasharray="4 4" fill="none"/><path d="M30 35 L40 28 L50 35" stroke-linecap="round" stroke-linejoin="round"/><path d="M32 42 L48 42" stroke-linecap="round"/><circle cx="35" cy="38" r="2" fill="#BFA89C"/><circle cx="45" cy="38" r="2" fill="#BFA89C"/></svg><p>没有找到证书</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = certs.map(c => `
            <tr>
                <td>${c.id.replace('user_', '').replace('_cert', '').substring(0, 12)}</td>
                <td>${c.cn}</td>
                <td>${c.org}</td>
                <td>${c.type}</td>
                <td><span class="hand-badge ${c.status === '有效' ? 'hand-badge-success' : c.status === '即将到期' ? 'hand-badge-warning' : 'hand-badge-danger'}">${c.status}</span></td>
                <td style="font-size:0.85rem">${c.issuedAt}</td>
                <td>
                    <button class="hand-btn hand-btn-sm" onclick="showCertDetail('${c.serial}')">查看</button>
                    ${c.status === '有效' ? `
                        <button class="hand-btn hand-btn-sm hand-btn-secondary" onclick="API.exportPem('${c.serial}')">PEM</button>
                        <button class="hand-btn hand-btn-sm" onclick="API.exportCrt('${c.serial}')">CRT(双击安装)</button>
                        <button class="hand-btn hand-btn-sm hand-btn-accent" onclick="exportP12('${c.serial}','${c.cn}')">导出P12</button>
                    ` : ''}
                    ${c.status === '有效' && currentUser && currentUser.role === 'ca_admin' ? `<button class="hand-btn hand-btn-sm hand-btn-danger" onclick="showRevokeModal('${c.serial}','${c.cn}')">吊销</button>` : ''}
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

async function showCertDetail(serial) {
    try {
        const cert = await API.getCertDetail(serial);
        const html = `
            <div class="detail-grid">
                <span class="detail-label">证书标识</span><span class="detail-value">${cert.id}</span>
                <span class="detail-label">序列号</span><span class="detail-value">${cert.serial}</span>
                <span class="detail-label">通用名称</span><span class="detail-value">${cert.cn}</span>
                <span class="detail-label">所属组织</span><span class="detail-value">${cert.org}</span>
                <span class="detail-label">证书类型</span><span class="detail-value">${cert.type}</span>
                <span class="detail-label">签发者</span><span class="detail-value">${cert.issuer}</span>
                <span class="detail-label">签发时间</span><span class="detail-value">${cert.issuedAt}</span>
                <span class="detail-label">到期时间</span><span class="detail-value">${cert.expiresAt} (剩余${cert.remainingDays}天)</span>
                <span class="detail-label">当前状态</span><span class="detail-value"><span class="hand-badge ${cert.status === '有效' ? 'hand-badge-success' : cert.status === '即将到期' ? 'hand-badge-warning' : 'hand-badge-danger'}">${cert.status}</span></span>
            </div>`;
        document.getElementById('modalCertBody').innerHTML = html;
        UI.showModal('cert');
    } catch (err) {
        UI.toast('加载证书详情失败: ' + err.message, 'error');
    }
}

/* ----- 证书申请 ----- */
async function handleCertApply(e) {
    e.preventDefault();
    const cn = document.getElementById('applyCN').value.trim();
    const org = document.getElementById('applyOrg').value.trim();
    if (!cn || !org) { UI.toast('请完整填写申请信息', 'warning'); return; }

    try {
        const resp = await API.applyCert(cn, org);
        UI.hideModal('cert-apply');
        document.getElementById('applyCN').value = '';
        document.getElementById('applyOrg').value = '';
        UI.toast('申请已提交：' + resp.csrId, 'success');
        if (document.getElementById('page-ra').classList.contains('active')) renderRARequests();
        renderMyApplications();
        renderHome();
    } catch (err) {
        UI.toast('申请失败: ' + err.message, 'error');
    }
}

/* ----- 用户管理 ----- */
async function renderUserManagement() {
    const tbody = document.getElementById('userTableBody');
    if (!tbody) return;

    try {
        const users = await API.getUsers();
        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5"><div class="hand-empty"><p>暂无用户</p></div></td></tr>';
            return;
        }
        tbody.innerHTML = users.map(u => {
            // 角色显示名称
            const roleName = {ca_admin: '👑 CA管理员', ra_operator: '🔍 RA操作员',
                              auditor: '📋 审计员', end_user: '👤 终端用户'}[u.role] || u.role;
            const isMe = currentUser && currentUser.id === u.username;
            const isAdmin = currentUser && currentUser.role === 'ca_admin';

            let actions = '';
            if (isAdmin && !isMe) {
                if (u.role === 'end_user') {
                    actions = `<button class="hand-btn hand-btn-sm hand-btn-accent" onclick="promoteUser('${u.username}')">提升为审核员</button>`;
                } else if (u.role === 'ra_operator') {
                    actions = `<button class="hand-btn hand-btn-sm hand-btn-secondary" onclick="demoteUser('${u.username}')">降级为普通用户</button>`;
                } else {
                    actions = '<span style="color:var(--color-text-light);font-size:0.85rem">不可操作</span>';
                }
            } else if (isMe) {
                actions = '<span style="color:var(--color-text-light);font-size:0.85rem">当前用户</span>';
            }

            return `<tr>
                <td>${u.username} ${isMe ? '<span style="color:var(--color-accent)">(我)</span>' : ''}</td>
                <td>${u.name || '-'}</td>
                <td><span class="hand-badge hand-badge-info">${roleName}</span></td>
                <td><span class="hand-badge ${u.active !== false ? 'hand-badge-success' : 'hand-badge-danger'}">${u.active !== false ? '正常' : '已禁用'}</span></td>
                <td>${actions || '-'}</td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

async function promoteUser(username) {
    if (!confirm(`确定将用户 ${username} 提升为权限审核员吗？`)) return;
    try {
        const resp = await API.promoteReviewer(username);
        UI.toast(resp.message || '提升成功', 'success');
        renderUserManagement();
    } catch (err) {
        UI.toast(err.message || '操作失败', 'error');
    }
}

async function demoteUser(username) {
    if (!confirm(`确定将用户 ${username} 降级为普通用户吗？`)) return;
    try {
        const resp = await API.demoteUser(username);
        UI.toast(resp.message || '降级成功', 'success');
        renderUserManagement();
    } catch (err) {
        UI.toast(err.message || '操作失败', 'error');
    }
}

/* ----- RA审核 ----- */
async function renderRARequests() {
    const tbody = document.getElementById('raTableBody');
    const filter = document.getElementById('raFilter').value;

    try {
        // 获取待审核列表(pending/first_approved)
        const items = await API.getCsrPending();
        // 也获取已批准待签发列表(approved但未issued)
        const approvedItems = await API.getCsrApproved();
        // 合并：只保留已批准但未签发的
        const pendingIssue = approvedItems.filter(a => !a.issued);
        const allItems = [...items, ...pendingIssue];

        let filtered = filter === 'all' ? allItems : allItems.filter(r => r.status === filter);

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>没有审核记录</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = filtered.map(r => {
            let statusText = r.statusText || '';
            if (r.status === 'approved') statusText = r.issued ? '已签发' : '待签发';
            const isApproved = r.status === 'approved';

            return `<tr>
                <td>${r.id}</td>
                <td>${r.cn}</td>
                <td>${r.org}</td>
                <td>${r.submittedAt}</td>
                <td><span class="hand-badge ${isApproved ? (r.issued ? 'hand-badge-success' : 'hand-badge-info') : r.status === 'pending' ? 'hand-badge-warning' : r.status === 'first_approved' ? 'hand-badge-info' : 'hand-badge-danger'}">${statusText}</span></td>
                <td style="font-size:0.85rem">${isApproved ? 'CA签发' : r.currentApprover}</td>
                <td>
                    ${isApproved && !r.issued ? `<button class="hand-btn hand-btn-sm hand-btn-primary" onclick="issueCertCSR('${r.id}')">签发证书</button>` : ''}
                    ${r.status === 'pending' || r.status === 'first_approved' ? `
                        <button class="hand-btn hand-btn-sm hand-btn-primary" onclick="approveCSR('${r.id}','${r.status}')">通过</button>
                        <button class="hand-btn hand-btn-sm hand-btn-danger" onclick="rejectCSR('${r.id}')">拒绝</button>
                    ` : (!isApproved ? '<span style="font-size:0.8rem;color:var(--color-text-light)">已完成</span>' : '')}
                </td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

// ---- CSR 审核状态变量（用于模态框回调） ----
let _pendingApproveId = null;
let _pendingApproveStatus = null;
let _pendingRejectId = null;

async function approveCSR(id, status) {
    _pendingApproveId = id;
    _pendingApproveStatus = status;
    document.getElementById('csrNoteTitle').textContent = '审核意见';
    document.getElementById('csrNoteLabel').textContent = '审核意见(可选):';
    document.getElementById('csrNoteInput').value = '';
    document.getElementById('csrNoteInput').placeholder = '输入审核意见...';
    document.getElementById('csrNoteConfirm').onclick = doApproveCSR;
    UI.showModal('modal-csr-note');
}

async function doApproveCSR() {
    const id = _pendingApproveId;
    const status = _pendingApproveStatus;
    const note = document.getElementById('csrNoteInput').value || '';
    _pendingApproveId = null;
    _pendingApproveStatus = null;
    UI.hideModal('modal-csr-note');

    try {
        let resp;
        if (status === 'first_approved') {
            resp = await API.approveSecond(id, note);
        } else {
            resp = await API.approveFirst(id, note);
        }
        UI.toast(resp.message, 'success');
        renderRARequests();
        renderHome();
    } catch (err) {
        UI.toast('操作失败: ' + err.message, 'error');
        renderRARequests();
    }
}

async function rejectCSR(id) {
    _pendingRejectId = id;
    document.getElementById('csrNoteTitle').textContent = '拒绝原因';
    document.getElementById('csrNoteLabel').textContent = '请填写拒绝原因:';
    document.getElementById('csrNoteInput').value = '';
    document.getElementById('csrNoteInput').placeholder = '输入拒绝原因...';
    document.getElementById('csrNoteConfirm').onclick = doRejectCSR;
    UI.showModal('modal-csr-note');
}

async function doRejectCSR() {
    const id = _pendingRejectId;
    const reason = document.getElementById('csrNoteInput').value || '';
    _pendingRejectId = null;
    UI.hideModal('modal-csr-note');

    if (!reason) {
        UI.toast('请填写拒绝原因', 'warning');
        return;
    }
    try {
        const resp = await API.rejectCsr(id, reason);
        UI.toast(resp.message, 'warning');
        renderRARequests();
    } catch (err) {
        UI.toast('操作失败: ' + err.message, 'error');
    }
}

async function issueCertCSR(id) {
    if (!confirm(`确认签发证书 ${id}？`)) return;
    try {
        const resp = await API.issueCert(id);
        UI.toast(resp.message, 'success');
        renderRARequests();
        renderCertificates();
        renderHome();
    } catch (err) {
        UI.toast('签发失败: ' + err.message, 'error');
    }
}

/* ----- CRL吊销 ----- */
let _pendingP12Serial = null;
let _pendingP12Cn = null;

async function exportP12(serial, cn) {
    _pendingP12Serial = serial;
    _pendingP12Cn = cn;
    document.getElementById('p12Label').textContent = `为 ${cn} 设置导出密码:`;
    document.getElementById('p12PwdInput').value = 'p12_export_123';
    document.getElementById('p12ConfirmBtn').onclick = doExportP12;
    UI.showModal('modal-p12-pwd');
}

async function doExportP12() {
    const serial = _pendingP12Serial;
    const cn = _pendingP12Cn;
    const pwd = document.getElementById('p12PwdInput').value || '';
    _pendingP12Serial = null;
    _pendingP12Cn = null;
    UI.hideModal('modal-p12-pwd');

    if (!pwd || pwd.length < 6) {
        UI.toast('密码至少6位', 'warning');
        return;
    }
    try {
        await API.exportP12(serial, pwd);
        UI.toast('PKCS#12 已开始下载', 'success');
    } catch (err) {
        UI.toast('导出失败: ' + err.message, 'error');
    }
}

/* ----- CRL吊销 ----- */
async function renderRevokedList() {
    const tbody = document.getElementById('revokedTableBody');
    try {
        const items = await API.getRevoked();
        if (items.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>目前没有已吊销的证书</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = items.map(r => `
            <tr>
                <td>${r.serial}</td>
                <td>${r.cn}</td>
                <td>${r.revokedAt}</td>
                <td><span class="hand-badge hand-badge-danger">${r.reasonDesc}</span></td>
                <td>${r.revokedBy}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

function showRevokeModal(serial, cn) {
    document.getElementById('revokeSerial').value = serial;
    document.getElementById('revokeCn').value = cn;
    document.getElementById('revokeReason').value = 'keyCompromise';
    UI.showModal('cert-revoke');
}

async function handleRevoke(e) {
    e.preventDefault();
    const serial = document.getElementById('revokeSerial').value;
    const cn = document.getElementById('revokeCn').value;
    const reason = document.getElementById('revokeReason').value;
    const reasonText = document.querySelector('#revokeReason option:checked').textContent;

    try {
        const resp = await API.revokeCert(serial, cn, reason, reasonText);
        UI.hideModal('cert-revoke');
        UI.toast(resp.message, 'success');
        renderCertificates();
        if (document.getElementById('page-crl').classList.contains('active')) renderRevokedList();
        renderHome();
    } catch (err) {
        UI.toast('吊销失败: ' + err.message, 'error');
    }
}

async function generateCRL() {
    try {
        const resp = await API.generateCRL();
        UI.toast(resp.message, 'success');
    } catch (err) {
        UI.toast(err.message, 'warning');
    }
}

/* ----- OCSP 在线状态查询 ----- */
async function renderOcspStats() {
    const container = document.getElementById('ocspStatsContainer');
    if (!container) return;
    try {
        const stats = await API.getOcspStats();
        const items = [
            { label: '总请求数', value: stats.total_requests, color: '#4A90D9' },
            { label: '状态良好', value: stats.good_responses, color: '#52C41A' },
            { label: '已吊销', value: stats.revoked_responses, color: '#FF4D4F' },
            { label: '未知', value: stats.unknown_responses, color: '#FAAD14' },
            { label: '缓存命中', value: stats.cache_hits, color: '#722ED1' },
            { label: '缓存大小', value: stats.cacheSize, color: '#13C2C2' },
        ];
        container.innerHTML = items.map(i => `
            <div style="background:#f9f9f9;border-radius:8px;padding:12px;text-align:center;border-left:3px solid ${i.color}">
                <div style="font-size:1.6rem;font-weight:700;color:${i.color}">${i.value}</div>
                <div style="font-size:0.8rem;color:#666;margin-top:4px">${i.label}</div>
            </div>
        `).join('');
    } catch (err) {
        container.innerHTML = `<div style="color:#999;font-size:0.85rem">统计加载失败: ${err.message}</div>`;
    }
}

async function handleOcspQuery() {
    const input = document.getElementById('ocspSerialInput');
    const serial = input.value.trim();
    if (!serial) {
        UI.toast('请输入证书序列号', 'warning');
        return;
    }
    try {
        const result = await API.getOcspStatus(serial);
        const resultDiv = document.getElementById('ocspQueryResult');

        let statusHtml = '';
        if (result.statusLabel === 'good') {
            statusHtml = `<span style="display:inline-block;padding:2px 10px;border-radius:4px;background:#E8F5E9;color:#2E7D32;font-weight:600">状态良好 (GOOD)</span>`;
        } else if (result.statusLabel === 'revoked') {
            statusHtml = `<span style="display:inline-block;padding:2px 10px;border-radius:4px;background:#FFEBEE;color:#C62828;font-weight:600">已吊销 (REVOKED)</span>
                <div style="margin-top:6px;font-size:0.85rem">
                    <span style="color:#666">吊销时间:</span> ${result.revokedAt || '未知'}<br>
                    <span style="color:#666">吊销原因:</span> ${result.reasonDesc || result.reason || '未知'}
                </div>`;
        } else {
            statusHtml = `<span style="display:inline-block;padding:2px 10px;border-radius:4px;background:#FFF8E1;color:#F57F17;font-weight:600">未知证书 (UNKNOWN)</span>`;
        }

        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `
            <div style="background:#f5f5f5;border-radius:8px;padding:14px">
                <div style="font-size:0.85rem;color:#666;margin-bottom:6px">
                    序列号: <code style="background:#e8e8e8;padding:2px 6px;border-radius:3px">${result.serial}</code>
                    <span style="margin-left:16px">查询时间: ${new Date(result.checkedAt).toLocaleString('zh-CN')}</span>
                </div>
                <div>${statusHtml}</div>
            </div>
        `;
    } catch (err) {
        UI.toast('查询失败: ' + err.message, 'error');
    }
}

async function handleOcspQueryByFile() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.pem,.crt,.cer';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        try {
            // 先上传临时文件，再用路径查询
            const uploadResp = await fetch('/api/ocsp/check-file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: file.name })
            });
            // 由于浏览器无法直接获取本地路径，提示用户使用序列号查询
            UI.toast('请复制证书序列号后使用"查询状态"按钮', 'info');
        } catch (err) {
            UI.toast('文件查询暂不支持，请输入序列号查询', 'info');
        }
    };
    // 改为直接提示用户输入序列号就行（文件上传场景受限）
    UI.toast('请在输入框中粘贴证书序列号进行查询', 'info');
}

async function handleOcspClearCache() {
    try {
        const resp = await API.clearOcspCache();
        UI.toast(resp.message || 'OCSP缓存已清空', 'success');
        renderOcspStats();
    } catch (err) {
        UI.toast('清空缓存失败: ' + err.message, 'error');
    }
}

/* ----- 审计日志 ----- */
async function renderAuditLogs() {
    const tbody = document.getElementById('auditTableBody');
    const filter = document.getElementById('auditFilter').value;
    const search = document.getElementById('auditSearch').value.toLowerCase();

    try {
        let items = await API.getAuditLogs(50, filter === 'all' ? '' : filter);
        if (search) items = items.filter(l => l.user.includes(search) || l.detail.includes(search));

        if (items.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>没有匹配的日志</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = items.map(l => `
            <tr>
                <td style="font-size:0.85rem">${l.time}</td>
                <td>${l.user}</td>
                <td><span class="hand-badge hand-badge-info">${l.action}</span></td>
                <td><span class="hand-badge ${l.result === 'SUCCESS' ? 'hand-badge-success' : 'hand-badge-danger'}">${l.result}</span></td>
                <td style="font-size:0.85rem">${l.detail}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

/* ----- 我的申请记录 ----- */
async function renderMyApplications() {
    const tbody = document.getElementById('myAppTableBody');
    if (!tbody) return;
    try {
        const apps = await API.getMyApplications();
        if (apps.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>暂无申请记录</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = apps.map(a => {
            let badgeClass = 'hand-badge-warning';
            if (a.status === 'issued') badgeClass = 'hand-badge-success';
            else if (a.status === 'approved') badgeClass = 'hand-badge-info';
            else if (a.status === 'rejected') badgeClass = 'hand-badge-danger';
            return `<tr>
                <td style="font-size:0.85rem">${a.id}</td>
                <td>${a.cn}</td>
                <td>${a.org}</td>
                <td style="font-size:0.85rem">${a.submittedAt}</td>
                <td><span class="hand-badge ${badgeClass}">${a.statusText}</span></td>
            </tr>`;
        }).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

/* ----- 用户管理（仅admin可见） ----- */
async function renderUserManagement() {
    const tbody = document.getElementById('userTableBody');
    if (!tbody) return;
    try {
        const users = await API.getUsers();
        const roleMap = { 'ca_admin': 'CA管理员', 'ra_operator': '权限审核员', 'auditor': '审计员', 'end_user': '普通用户' };
        tbody.innerHTML = users.map(u => {
            if (u.id === 'admin') return ''; // 不显示admin自己
            const isEndUser = u.role === 'end_user';
            const isReviewer = u.role === 'ra_operator';
            return `<tr>
                <td>${u.id}</td>
                <td>${u.name}</td>
                <td><span class="hand-badge ${isReviewer ? 'hand-badge-info' : isEndUser ? 'hand-badge' : 'hand-badge-success'}">${roleMap[u.role] || u.role}</span></td>
                <td><span class="hand-badge hand-badge-success">${u.isActive ? '正常' : '已停用'}</span></td>
                <td>
                    ${isEndUser ? `<button class="hand-btn hand-btn-sm hand-btn-primary" onclick="promoteReviewer('${u.id}')">提升为审核员</button>` : ''}
                    ${isReviewer ? `<button class="hand-btn hand-btn-sm hand-btn-warning" onclick="demoteUser('${u.id}')">降级为用户</button>` : ''}
                    <span style="font-size:0.8rem;color:var(--color-text-light)">${u.role === 'auditor' ? '审计员' : u.role === 'ca_admin' ? '管理员' : ''}</span>
                </td>
            </tr>`;
        }).join('');
        // 清理空行
        tbody.innerHTML = tbody.innerHTML.replace(/<tr><\/tr>/g, '');
        if (!tbody.innerHTML.trim()) {
            tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>暂无其他用户</p></div></td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

async function promoteReviewer(username) {
    if (!confirm(`确认将用户 "${username}" 提升为权限审核员？`)) return;
    try {
        const resp = await API.promoteReviewer(username);
        UI.toast(resp.message, 'success');
        renderUserManagement();
    } catch (err) {
        UI.toast(err.message, 'error');
    }
}

async function demoteUser(username) {
    if (!confirm(`确认将用户 "${username}" 降级为普通用户？`)) return;
    try {
        const resp = await API.demoteUser(username);
        UI.toast(resp.message, 'warning');
        renderUserManagement();
    } catch (err) {
        UI.toast(err.message, 'error');
    }
}

/* ----- 证书申请 ----- */
async function renderBackups() {
    const tbody = document.getElementById('backupTableBody');
    try {
        const items = await API.getBackups();
        if (items.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>还没有备份记录</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = items.map(b => `
            <tr>
                <td style="font-size:0.85rem">${b.name}</td>
                <td>${b.size}</td>
                <td>${b.createdAt}</td>
                <td>${b.type}</td>
                <td><span class="hand-badge hand-badge-success">${b.status}</span></td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

async function createBackup() {
    try {
        const resp = await API.createBackup();
        UI.toast(resp.message, 'success');
        renderBackups();
    } catch (err) {
        UI.toast('备份失败: ' + err.message, 'error');
    }
}

// ============================================================
// TSA 时间戳服务
// ============================================================

async function renderTsaStatus() {
    try {
        const status = await API.getTsaStatus();
        document.getElementById('tsaStatConfigured').textContent = status.configured ? '✅ 已配置' : '❌ 未配置';
        document.getElementById('tsaStatNtp').textContent = status.timeSource?.available ? '🟢 已同步' : '🟡 系统时间';
        document.getElementById('tsaStatTotal').textContent = status.totalIssued || 0;
        document.getElementById('tsaStatRate').textContent = `${status.rateLimit || 500}/秒`;

        const certEl = document.getElementById('tsaCertInfo');
        if (status.certificate) {
            certEl.innerHTML = `🔒 TSA证书: ${status.certificate.subject} | 有效期: ${status.certificate.validFrom?.substring(0,10)} ~ ${status.certificate.validTo?.substring(0,10)}`;
        } else {
            certEl.innerHTML = '⚠️ TSA证书未配置，请先通过命令行签发：python scripts/setup_tsa_certificate.py';
        }
    } catch (err) {
        document.getElementById('tsaStatConfigured').textContent = '❌ 错误';
        document.getElementById('tsaStatNtp').textContent = '-';
        document.getElementById('tsaStatTotal').textContent = '-';
        document.getElementById('tsaStatRate').textContent = '-';
    }
}

async function renderTsaRecords() {
    const tbody = document.getElementById('tsaRecordsBody');
    try {
        const records = await API.getTsaRecords(50);
        if (records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6"><div class="hand-empty"><p>暂无时间戳签发记录</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = records.map(r => `
            <tr>
                <td><code style="font-size:0.8rem">${r.serialNumber ? r.serialNumber.substring(0, 16) + '...' : '-'}</code></td>
                <td>${r.hashAlgorithm || '-'}</td>
                <td>${r.genTime || '-'}</td>
                <td>${r.requester || '-'}</td>
                <td>${r.clientIp || '-'}</td>
                <td><span class="badge badge-success">${r.status || '-'}</span></td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

async function renderScenarioRecords() {
    const tbody = document.getElementById('scenarioRecordsBody');
    const filter = document.getElementById('scenarioFilter')?.value || '';
    try {
        const records = await API.getScenarioRecords(filter, 50);
        if (records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6"><div class="hand-empty"><p>暂无业务场景记录</p></div></td></tr>`;
            return;
        }
        const typeNames = { contract_sign: '📄 电子合同', code_release: '💻 代码发布', archive: '📁 档案归档' };
        tbody.innerHTML = records.map(r => `
            <tr>
                <td>${typeNames[r.scenarioType] || r.scenarioType}</td>
                <td><code style="font-size:0.8rem">${r.bizId || '-'}</code></td>
                <td><code style="font-size:0.8rem">${r.tstSerial ? r.tstSerial.substring(0, 12) + '...' : '-'}</code></td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${r.bizDesc || ''}">${r.bizDesc || '-'}</td>
                <td>${r.createdBy || '-'}</td>
                <td>${r.createdAt || '-'}</td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

// --- TSA 模态框事件绑定 ---

// --- TSA 选项卡切换（三模式） ---
function switchTstTab(mode) {
    const hashMode = document.getElementById('tstHashMode');
    const fileMode = document.getElementById('tstFileMode');
    const textMode = document.getElementById('tstTextMode');
    const tabHash = document.getElementById('tstTabHash');
    const tabFile = document.getElementById('tstTabFile');
    const tabText = document.getElementById('tstTabText');
    const resultArea = document.getElementById('tstResultArea');
    resultArea.style.display = 'none';

    // 全部隐藏
    hashMode.style.display = 'none';
    fileMode.style.display = 'none';
    textMode.style.display = 'none';
    [tabHash, tabFile, tabText].forEach(t => {
        t.style.borderBottomColor = 'transparent';
        t.style.fontWeight = 'normal';
    });
    document.getElementById('tstHashValue').required = false;

    if (mode === 'hash') {
        hashMode.style.display = 'block';
        tabHash.style.borderBottomColor = 'var(--color-primary)';
        tabHash.style.fontWeight = 'bold';
        document.getElementById('tstHashValue').required = true;
    } else if (mode === 'file') {
        fileMode.style.display = 'block';
        tabFile.style.borderBottomColor = 'var(--color-primary)';
        tabFile.style.fontWeight = 'bold';
    } else if (mode === 'text') {
        textMode.style.display = 'block';
        tabText.style.borderBottomColor = 'var(--color-primary)';
        tabText.style.fontWeight = 'bold';
    }
}

// 文件预览 + 自动计算哈希
async function previewTstFile() {
    const fileInput = document.getElementById('tstFileInput');
    const fileInfo = document.getElementById('tstFileInfo');
    const fileHashDiv = document.getElementById('tstFileHash');
    const fileHashInput = document.getElementById('tstFileHashValue');

    if (!fileInput.files || fileInput.files.length === 0) {
        fileInfo.style.display = 'none';
        fileHashDiv.style.display = 'none';
        return;
    }

    const file = fileInput.files[0];
    const sizeStr = file.size < 1024 ? `${file.size} B` :
        file.size < 1024 * 1024 ? `${(file.size / 1024).toFixed(1)} KB` :
        `${(file.size / (1024 * 1024)).toFixed(1)} MB`;

    fileInfo.style.display = 'block';
    fileInfo.innerHTML = `📄 ${file.name} (${sizeStr})`;

    // 自动计算哈希
    const algo = document.getElementById('tstHashAlgorithm').value;
    try {
        const buffer = await file.arrayBuffer();
        let hashHex;
        if (algo === 'sm3') {
            hashHex = '（SM3 将提交到后端计算）';
        } else {
            const hashName = algo === 'sha256' ? 'SHA-256' : algo === 'sha384' ? 'SHA-384' : 'SHA-512';
            const hashBuffer = await crypto.subtle.digest(hashName, buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
        fileHashInput.value = hashHex;
        fileHashDiv.style.display = 'block';
    } catch (e) {
        console.warn('前端哈希计算失败:', e);
        fileHashInput.value = '（将在服务端计算）';
        fileHashDiv.style.display = 'block';
    }
}

// 文本模式实时预览
function previewTstText() {
    const content = document.getElementById('tstTextContent').value;
    const preview = document.getElementById('tstTextPreview');
    if (content.trim()) {
        preview.style.display = 'block';
        preview.innerHTML = `📝 内容长度: ${content.length} 字符 | 预览: ${content.substring(0, 60).replace(/\n/g, ' ')}${content.length > 60 ? '...' : ''}`;
    } else {
        preview.style.display = 'none';
    }
}

// 绑定文本输入实时预览
document.addEventListener('DOMContentLoaded', function() {
    const textContent = document.getElementById('tstTextContent');
    if (textContent) textContent.addEventListener('input', previewTstText);
});

function showTstRequestModal() {
    document.getElementById('tstResultArea').style.display = 'none';
    document.getElementById('tstRequestForm').reset();
    document.getElementById('tstFileInfo').style.display = 'none';
    document.getElementById('tstFileHash').style.display = 'none';
    document.getElementById('tstTextPreview').style.display = 'none';
    switchTstTab('hash');
    UI.showModal('modal-tst-request');
}

function showTstVerifyModal(token) {
    document.getElementById('tstVerifyResult').style.display = 'none';
    document.getElementById('tstVerifyForm').reset();
    if (token) {
        document.getElementById('tstTokenInput').value = token;
    }
    UI.showModal('modal-tst-verify');
}

// 复制时间戳结果
function copyTstResult() {
    const resultContent = document.getElementById('tstResultContent');
    if (!resultContent) return;
    const text = resultContent.innerText || resultContent.textContent;
    navigator.clipboard.writeText(text).then(() => {
        UI.toast('已复制到剪贴板', 'success');
    }).catch(() => {
        UI.toast('复制失败，请手动选择复制', 'error');
    });
}

function showContractSignModal() {
    document.getElementById('contractSignResult').style.display = 'none';
    document.getElementById('contractSignForm').reset();
    UI.showModal('modal-contract-sign');
}

function showCodeReleaseModal() {
    document.getElementById('codeReleaseResult').style.display = 'none';
    document.getElementById('codeReleaseForm').reset();
    UI.showModal('modal-code-release');
}

function showArchiveModal() {
    document.getElementById('archiveResult').style.display = 'none';
    document.getElementById('archiveForm').reset();
    UI.showModal('modal-archive');
}

// ============================================================
// 手绘动画 - 按钮涟漪
// ============================================================
document.addEventListener('click', function(e) {
    const btn = e.target.closest('.hand-btn');
    if (!btn) return;
    const ripple = document.createElement('span');
    ripple.className = 'ripple';
    const rect = btn.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = (e.clientX - rect.left - size / 2) + 'px';
    ripple.style.top = (e.clientY - rect.top - size / 2) + 'px';
    btn.appendChild(ripple);
    ripple.addEventListener('animationend', () => ripple.remove());
});

// Enter登录
document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && document.getElementById('loginPage').style.display !== 'none') {
        const loginBtn = document.querySelector('#loginPage .hand-btn-primary');
        if (loginBtn) loginBtn.click();
    }
});

// ============================================================
// 初始化
// ============================================================
document.addEventListener('DOMContentLoaded', async function() {
    document.getElementById('loginPage').style.display = 'flex';
    document.getElementById('loginCard').style.display = 'block';
    document.getElementById('registerCard').style.display = 'none';
    document.getElementById('appContainer').style.display = 'none';

    // 日期
    document.getElementById('todayDate').textContent = new Date().toLocaleDateString('zh-CN', {
        year: 'numeric', month: 'long', day: 'numeric', weekday: 'long'
    });

    // 事件绑定
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('registerForm').addEventListener('submit', handleRegister);
    document.getElementById('menuBtn').addEventListener('click', () => {
        document.getElementById('sideMenu').classList.contains('open') ? closeMenu() : openMenu();
    });
    document.getElementById('menuOverlay').addEventListener('click', closeMenu);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('certApplyForm').addEventListener('submit', handleCertApply);
    document.getElementById('revokeForm').addEventListener('submit', handleRevoke);

    // 过滤器和搜索
    ['certStatusFilter', 'certSearch'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('input', renderCertificates);
            el.addEventListener('change', renderCertificates);
        }
    });
    ['raFilter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', renderRARequests);
    });
    ['auditFilter', 'auditSearch'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('input', renderAuditLogs);
            el.addEventListener('change', renderAuditLogs);
        }
    });

    // --- TSA 表单提交处理（三模式） ---
    document.getElementById('tstRequestForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const hashAlgo = document.getElementById('tstHashAlgorithm').value;
        const nonceInput = document.getElementById('tstNonce').value;
        const requester = document.getElementById('tstRequester').value.trim();
        const nonce = nonceInput ? parseInt(nonceInput) : null;

        const isFileMode = document.getElementById('tstFileMode').style.display !== 'none';
        const isTextMode = document.getElementById('tstTextMode').style.display !== 'none';

        let result;
        try {
            if (isFileMode) {
                // 文件上传模式 — 上传 → 系统算哈希 → 签时间戳
                const fileInput = document.getElementById('tstFileInput');
                if (!fileInput.files || fileInput.files.length === 0) {
                    UI.toast('请选择文件', 'error');
                    return;
                }
                result = await API.requestFileTimestamp(fileInput.files[0], hashAlgo);
            } else if (isTextMode) {
                // 文本输入模式 — 输入文字 → 系统算哈希 → 签时间戳
                const content = document.getElementById('tstTextContent').value.trim();
                if (!content) {
                    UI.toast('请输入文本内容', 'error');
                    return;
                }
                const title = document.getElementById('tstTextTitle').value.trim();
                result = await API.requestTextTimestamp(content, hashAlgo, title);
            } else {
                // 哈希输入模式 — 用户自己提供哈希 → 签时间戳
                const hashValue = document.getElementById('tstHashValue').value.trim();
                if (!hashValue) {
                    UI.toast('请输入哈希值', 'error');
                    return;
                }
                result = await API.requestTimestamp(hashValue, hashAlgo, nonce, requester);
            }

            // --- 结果展示（三模式统一） ---
            const area = document.getElementById('tstResultArea');
            area.style.display = 'block';

            let resultHtml = `<table style="width:100%;border-collapse:collapse;font-size:0.85rem">
                <tr><td style="padding:4px 8px;font-weight:bold">状态</td><td style="padding:4px 8px">${result.statusString || '✅ 已签发'}</td></tr>`;

            // 内容来源信息
            if (result.fileInfo) {
                resultHtml += `<tr><td style="padding:4px 8px;font-weight:bold">文件</td><td style="padding:4px 8px">📄 ${result.fileInfo.fileName} (${result.fileInfo.fileSizeStr})</td></tr>`;
            } else if (result.contentInfo) {
                resultHtml += `<tr><td style="padding:4px 8px;font-weight:bold">内容</td><td style="padding:4px 8px">✏️ ${result.contentInfo.title} (${result.contentInfo.contentLength} 字符)</td></tr>`;
                if (result.contentInfo.preview) {
                    resultHtml += `<tr><td style="padding:4px 8px;font-weight:bold">预览</td><td style="padding:4px 8px;color:var(--color-text-light)">${result.contentInfo.preview}</td></tr>`;
                }
            }

            resultHtml += `
                <tr><td style="padding:4px 8px;font-weight:bold">序列号</td><td style="padding:4px 8px"><code style="font-size:0.75rem">${result.serialNumber || '-'}</code></td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">签发时间</td><td style="padding:4px 8px">${result.genTime || '-'}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">哈希算法</td><td style="padding:4px 8px">${result.hashAlgorithm?.toUpperCase() || hashAlgo.toUpperCase()}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">哈希值</td><td style="padding:4px 8px"><code style="font-size:0.7rem;word-break:break-all">${result.hashValue || '-'}</code></td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">NTP 时间源</td><td style="padding:4px 8px">${result.ntpAvailable ? '✅ 已同步' : '❌ 未同步（本地时间）'}</td></tr>
                <tr><td style="padding:4px 8px;font-weight:bold">时间偏差</td><td style="padding:4px 8px">${(result.driftSeconds * 1000).toFixed(2)} ms</td></tr>
            `;

            // 令牌预览
            const tokenPreview = result.tstToken ? result.tstToken.substring(0, 48) + '...' : '';
            if (tokenPreview) {
                resultHtml += `<tr><td style="padding:4px 8px;font-weight:bold">令牌（预览）</td><td style="padding:4px 8px"><code style="font-size:0.65rem;word-break:break-all">${tokenPreview}</code></td></tr>`;
            }

            resultHtml += `</table>`;

            // 存储令牌到隐藏元素，供验证按钮使用
            resultHtml += `<div id="tstResultToken" style="display:none">${result.tstToken || ''}</div>`;

            document.getElementById('tstResultContent').innerHTML = resultHtml;
            UI.toast('时间戳签发成功！', 'success');
            renderTsaRecords();
        } catch (err) {
            UI.toast('时间戳签发失败: ' + err.message, 'error');
        }
    });

    // TST Verify
    document.getElementById('tstVerifyForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const tstToken = document.getElementById('tstTokenInput').value.trim();
        const originalHash = document.getElementById('tstOriginalHash').value.trim() || null;
        try {
            const result = await API.verifyTimestamp(tstToken, originalHash);
            const area = document.getElementById('tstVerifyResult');
            area.style.display = 'block';
            if (result.valid) {
                let infoHtml = `<div class="hand-card" style="background:#f0fff0">
                    <h4 style="color:#2e7d32">✅ 时间戳验证通过</h4>
                    <p>${result.message}</p>
                    <table style="width:100%;border-collapse:collapse;font-size:0.85rem;margin-top:8px">`;
                if (result.tstInfo) {
                    infoHtml += `
                        <tr><td style="padding:4px 8px;font-weight:bold">哈希算法</td><td style="padding:4px 8px">${result.tstInfo.hashAlgorithm || '-'}</td></tr>
                        <tr><td style="padding:4px 8px;font-weight:bold">序列号</td><td style="padding:4px 8px"><code>${result.tstInfo.serialNumber || '-'}</code></td></tr>
                        <tr><td style="padding:4px 8px;font-weight:bold">签发时间</td><td style="padding:4px 8px">${result.tstInfo.genTime || '-'}</td></tr>
                        <tr><td style="padding:4px 8px;font-weight:bold">哈希值</td><td style="padding:4px 8px"><code style="font-size:0.7rem;word-break:break-all">${result.tstInfo.hashValue ? result.tstInfo.hashValue.substring(0, 48) + '...' : '-'}</code></td></tr>
                    `;
                }
                if (result.hashMatch !== null) {
                    infoHtml += `<tr><td style="padding:4px 8px;font-weight:bold;color:${result.hashMatch ? '#2e7d32' : '#c62828'}">哈希一致性</td><td style="padding:4px 8px">${result.hashMatch ? '✅ 与原始数据匹配' : '❌ 与原始数据不匹配'}</td></tr>`;
                }
                if (result.signerInfo) {
                    infoHtml += `
                        <tr><td style="padding:4px 8px;font-weight:bold">签名证书</td><td style="padding:4px 8px">${result.signerInfo.subject || '-'}</td></tr>
                        <tr><td style="padding:4px 8px;font-weight:bold">证书有效期</td><td style="padding:4px 8px">${result.signerInfo.validFrom || '-'} ~ ${result.signerInfo.validTo || '-'}</td></tr>
                        <tr><td style="padding:4px 8px;font-weight:bold">证书状态</td><td style="padding:4px 8px">${result.signerInfo.isValid ? '✅ 有效期内' : '❌ 已过期'}</td></tr>
                    `;
                }
                infoHtml += `</table></div>`;
                area.innerHTML = infoHtml;
            } else {
                area.innerHTML = `<div class="hand-card" style="background:#fff0f0"><h4 style="color:#c62828">❌ 验证失败</h4><p>${result.message}</p></div>`;
            }
        } catch (err) {
            UI.toast('验证失败: ' + err.message, 'error');
        }
    });

    // Contract Sign
    document.getElementById('contractSignForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const contractId = document.getElementById('contractId').value.trim();
        const contractHash = document.getElementById('contractHash').value.trim();
        const signerId = document.getElementById('signerId').value.trim();
        try {
            const result = await API.contractSignTimestamp(contractId, contractHash, signerId);
            const area = document.getElementById('contractSignResult');
            area.style.display = 'block';
            area.innerHTML = `
                <div class="hand-card" style="background:#f0fff0">
                    <h4 style="color:#2e7d32">✅ ${result.message}</h4>
                    <p>合同: ${result.contractId} | 签署人: ${result.signerId}</p>
                    <p>TST序列号: ${result.timestamp?.serialNumber || '-'}</p>
                    <p>生成时间: ${result.timestamp?.genTime || '-'}</p>
                </div>
            `;
            UI.toast(result.message, 'success');
            UI.hideModal('modal-contract-sign');
            renderScenarioRecords();
        } catch (err) {
            UI.toast('操作失败: ' + err.message, 'error');
        }
    });

    // Code Release
    document.getElementById('codeReleaseForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const repoName = document.getElementById('repoName').value.trim();
        const commitHash = document.getElementById('commitHash').value.trim();
        const branch = document.getElementById('repoBranch').value.trim() || 'main';
        const tag = document.getElementById('repoTag').value.trim();
        try {
            const result = await API.codeReleaseTimestamp(repoName, commitHash, branch, tag);
            const area = document.getElementById('codeReleaseResult');
            area.style.display = 'block';
            area.innerHTML = `
                <div class="hand-card" style="background:#f0fff0">
                    <h4 style="color:#2e7d32">✅ ${result.message}</h4>
                    <p>仓库: ${result.repoName} | 提交: ${result.commitHash?.substring(0, 16)}...</p>
                    <p>TST序列号: ${result.timestamp?.serialNumber || '-'}</p>
                </div>
            `;
            UI.toast(result.message, 'success');
            UI.hideModal('modal-code-release');
            renderScenarioRecords();
        } catch (err) {
            UI.toast('操作失败: ' + err.message, 'error');
        }
    });

    // Archive
    document.getElementById('archiveForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const archiveId = document.getElementById('archiveId').value.trim();
        const archiveHash = document.getElementById('archiveHash').value.trim();
        const archiveName = document.getElementById('archiveName').value.trim();
        const department = document.getElementById('archiveDept').value.trim();
        try {
            const result = await API.archiveTimestamp(archiveId, archiveHash, archiveName, '', department);
            const area = document.getElementById('archiveResult');
            area.style.display = 'block';
            area.innerHTML = `
                <div class="hand-card" style="background:#f0fff0">
                    <h4 style="color:#2e7d32">✅ ${result.message}</h4>
                    <p>档案: ${result.archiveId} | 名称: ${result.archiveName || '-'}</p>
                    <p>TST序列号: ${result.timestamp?.serialNumber || '-'}</p>
                </div>
            `;
            UI.toast(result.message, 'success');
            UI.hideModal('modal-archive');
            renderScenarioRecords();
        } catch (err) {
            UI.toast('操作失败: ' + err.message, 'error');
        }
    });
});
