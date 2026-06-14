/**
 * PKI系统 - 手绘风格前端交互逻辑 v1.0
 * 全链路对接后端API，无模拟数据
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
        UI.showModal('modal-cert');
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
        renderHome();
    } catch (err) {
        UI.toast('申请失败: ' + err.message, 'error');
    }
}

/* ----- RA审核 ----- */
async function renderRARequests() {
    const tbody = document.getElementById('raTableBody');
    const filter = document.getElementById('raFilter').value;

    try {
        const items = await API.getCsrPending();
        let filtered = filter === 'all' ? items : items.filter(r => r.status === filter);

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>没有审核记录</p></div></td></tr>`;
            return;
        }
        tbody.innerHTML = filtered.map(r => `
            <tr>
                <td>${r.id}</td>
                <td>${r.cn}</td>
                <td>${r.org}</td>
                <td>${r.submittedAt}</td>
                <td><span class="hand-badge ${r.status === 'pending' ? 'hand-badge-warning' : r.status === 'first_approved' ? 'hand-badge-info' : r.status === 'approved' ? 'hand-badge-success' : 'hand-badge-danger'}">${r.statusText}</span></td>
                <td style="font-size:0.85rem">${r.currentApprover}</td>
                <td>
                    ${r.status === 'pending' || r.status === 'first_approved' ? `
                        <button class="hand-btn hand-btn-sm hand-btn-primary" onclick="approveCSR('${r.id}','${r.status}')">通过</button>
                        <button class="hand-btn hand-btn-sm hand-btn-danger" onclick="rejectCSR('${r.id}')">拒绝</button>
                    ` : '<span style="font-size:0.8rem;color:var(--color-text-light)">已完成</span>'}
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

async function approveCSR(id, status) {
    const note = prompt('审核意见(可选):') || '';
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
    const reason = prompt('填写拒绝原因:');
    if (!reason) return;
    try {
        const resp = await API.rejectCsr(id, reason);
        UI.toast(resp.message, 'warning');
        renderRARequests();
    } catch (err) {
        UI.toast('操作失败: ' + err.message, 'error');
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
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>加载失败: ${err.message}</p></div></td></tr>`;
    }
}

/* ----- 备份管理 ----- */
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
// 手绘动效 - 按钮涟漪
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
    document.getElementById('appContainer').style.display = 'none';

    // 日期
    document.getElementById('todayDate').textContent = new Date().toLocaleDateString('zh-CN', {
        year: 'numeric', month: 'long', day: 'numeric', weekday: 'long'
    });

    // 事件绑定
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
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
});
