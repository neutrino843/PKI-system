/**
 * PKI系统 - 治愈系手绘风格前端 v1.0
 * 交互逻辑与路由控制
 * 
 * 功能模块：证书管理、RA审核、CRL吊销、审计日志、备份管理、系统设置
 */

// ============================================================
// 模拟数据层
// ============================================================
const PKI_DATA = {
    // 登录用户
    currentUser: null,
    users: [
        { id: 'admin', name: '管理员小美', role: 'ca_admin', roleName: 'CA管理员' },
        { id: 'ra_zhang', name: '审核员小张', role: 'ra_operator', roleName: 'RA操作员' },
        { id: 'auditor_li', name: '审计员小李', role: 'auditor', roleName: '审计员' },
        { id: 'user_wang', name: '用户小王', role: 'end_user', roleName: '终端用户' },
    ],
    credentials: {
        'admin': 'admin123',
        'ra_zhang': 'ra123456',
        'auditor_li': 'audit123',
        'user_wang': 'user1234',
    },
    // 证书数据
    certificates: [
        { id: 'CERT-001', serial: '0x9A3F2B1C', cn: '张三', org: '技术部', type: '用户证书', issuedAt: '2026-03-15', expiresAt: '2027-03-15', status: '有效', issuer: '中间CA' },
        { id: 'CERT-002', serial: '0x8B4E7D2F', cn: '李四', org: '市场部', type: '用户证书', issuedAt: '2026-04-01', expiresAt: '2027-04-01', status: '有效', issuer: '中间CA' },
        { id: 'CERT-003', serial: '0x6C5A9E3D', cn: '王五', org: '研发部', type: '用户证书', issuedAt: '2026-05-10', expiresAt: '2027-05-10', status: '已吊销', issuer: '中间CA' },
        { id: 'CERT-004', serial: '0x2D8F1E4A', cn: '内部服务A', org: '系统', type: '服务器证书', issuedAt: '2026-02-01', expiresAt: '2026-08-01', status: '有效', issuer: '中间CA' },
        { id: 'CERT-005', serial: '0x5E7B3C9A', cn: '内部服务B', org: '系统', type: '服务器证书', issuedAt: '2026-01-15', expiresAt: '2026-07-15', status: '即将到期', issuer: '中间CA' },
        { id: 'CERT-006', serial: '0x9C4F8A2E', cn: '测试用户', org: '测试部', type: '用户证书', issuedAt: '2026-06-01', expiresAt: '2027-06-01', status: '有效', issuer: '中间CA' },
    ],
    // CSR申请
    csrRequests: [
        { id: 'CSR-001', cn: '赵六', org: '财务部', submittedAt: '2026-06-10 14:30', status: 'pending', currentApprover: '初审待审核' },
        { id: 'CSR-002', cn: '孙七', org: '人事部', submittedAt: '2026-06-11 09:15', status: 'first_approved', firstBy: '审核员小张', currentApprover: '二审待审核' },
        { id: 'CSR-003', cn: '周八', org: '运维部', submittedAt: '2026-06-12 16:45', status: 'rejected', rejectReason: '身份信息不完整' },
    ],
    // 吊销记录
    revokedCerts: [
        { serial: '0x6C5A9E3D', cn: '王五', revokedAt: '2026-06-01 10:00', reason: '私钥泄露', revokedBy: '管理员小美' },
    ],
    // 审计日志
    auditLogs: [
        { time: '2026-06-14 08:00:00', user: '管理员小美', action: 'LOGIN', resource: '系统', result: 'SUCCESS', detail: '管理员登录系统' },
        { time: '2026-06-14 08:05:00', user: '管理员小美', action: 'ISSUE_CERT', resource: '证书CERT-006', result: 'SUCCESS', detail: '为用户test签发证书' },
        { time: '2026-06-14 08:10:00', user: '审核员小张', action: 'APPROVE_CSR', resource: 'CSR-002', result: 'SUCCESS', detail: '初审通过CSR-002' },
        { time: '2026-06-14 08:15:00', user: '审计员小李', action: 'VIEW_LOG', resource: '审计日志', result: 'SUCCESS', detail: '查看审计日志' },
        { time: '2026-06-14 08:20:00', user: '用户小王', action: 'LOGIN', resource: '系统', result: 'FAILURE', detail: '密码错误(第2次)' },
        { time: '2026-06-14 08:22:00', user: '用户小王', action: 'LOGIN', resource: '系统', result: 'SUCCESS', detail: '登录成功' },
        { time: '2026-06-14 08:30:00', user: '管理员小美', action: 'REVOKE', resource: '证书0x6C5A9E3D', result: 'SUCCESS', detail: '吊销王五证书-私钥泄露' },
        { time: '2026-06-14 08:35:00', user: '管理员小美', action: 'GEN_CRL', resource: 'CRL', result: 'SUCCESS', detail: '生成并发布CRL' },
        { time: '2026-06-14 09:00:00', user: '审核员小张', action: 'LOGOUT', resource: '系统', result: 'SUCCESS', detail: '登出系统' },
    ],
    // 备份记录
    backups: [
        { name: 'pki_backup_20260614_080000.enc', size: '2.4MB', createdAt: '2026-06-14 08:00', type: '全量备份', status: '正常' },
        { name: 'pki_backup_20260613_080000.enc', size: '2.3MB', createdAt: '2026-06-13 08:00', type: '全量备份', status: '正常' },
        { name: 'pki_backup_20260612_080000.enc', size: '2.3MB', createdAt: '2026-06-12 08:00', type: '全量备份', status: '正常' },
    ],
};

// ============================================================
// 工具函数
// ============================================================
const UI = {
    toast(msg, type = 'info') {
        const container = document.getElementById('toastContainer');
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.innerHTML = `<span>${msg}</span>`;
        container.appendChild(el);
        setTimeout(() => { el.classList.add('toast-out'); setTimeout(() => el.remove(), 300); }, 3000);
    },
    showModal(id) { document.getElementById(id).classList.add('show'); },
    hideModal(id) { document.getElementById(id).classList.remove('show'); },
    modal(name) { return document.getElementById(`modal-${name}`); },
};

// ============================================================
// 路由系统
// ============================================================
function navigateTo(page) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const target = document.getElementById(`page-${page}`);
    if (target) {
        target.classList.add('active');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    // 更新菜单高亮
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    const activeMenuItem = document.querySelector(`.menu-item[data-page="${page}"]`);
    if (activeMenuItem) activeMenuItem.classList.add('active');
    // 关闭菜单
    closeMenu();
}

// ============================================================
// 菜单控制
// ============================================================
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
// 页面渲染函数
// ============================================================

/* ----- 登录页 ----- */
function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
    const errorEl = document.getElementById('loginError');

    const expectedPwd = PKI_DATA.credentials[username];
    if (expectedPwd && expectedPwd === password) {
        PKI_DATA.currentUser = PKI_DATA.users.find(u => u.id === username);
        errorEl.classList.remove('show');
        document.getElementById('loginPage').style.display = 'none';
        document.getElementById('appContainer').style.display = 'block';
        updateUserInfo();
        navigateTo('home');
        UI.toast(`欢迎回来，${PKI_DATA.currentUser.name}！`, 'success');
    } else {
        errorEl.textContent = '✎ 用户名或密码不对，再试试吧~';
        errorEl.classList.add('show');
        document.getElementById('loginPassword').value = '';
    }
}

function handleLogout() {
    if (confirm('✎ 确定要离开吗？')) {
        PKI_DATA.currentUser = null;
        document.getElementById('appContainer').style.display = 'none';
        document.getElementById('loginPage').style.display = 'flex';
        document.getElementById('loginUsername').value = '';
        document.getElementById('loginPassword').value = '';
        UI.toast('已安全退出，下次见~', 'info');
    }
}

function updateUserInfo() {
    if (PKI_DATA.currentUser) {
        document.getElementById('userName').textContent = PKI_DATA.currentUser.name;
        document.getElementById('userRole').textContent = PKI_DATA.currentUser.roleName;
    }
}

/* ----- 首页 ----- */
function renderHome() {
    // 统计
    const valid = PKI_DATA.certificates.filter(c => c.status === '有效').length;
    const expiring = PKI_DATA.certificates.filter(c => c.status === '即将到期').length;
    const revoked = PKI_DATA.certificates.filter(c => c.status === '已吊销').length;
    document.getElementById('statCerts').textContent = PKI_DATA.certificates.length;
    document.getElementById('statValid').textContent = valid;
    document.getElementById('statExpiring').textContent = expiring;
    document.getElementById('statRevoked').textContent = revoked;

    // 功能磁贴在HTML中已静态实现
}

/* ----- 证书列表 ----- */
function renderCertificates() {
    const tbody = document.getElementById('certTableBody');
    const statusFilter = document.getElementById('certStatusFilter').value;
    const search = document.getElementById('certSearch').value.toLowerCase();

    let filtered = PKI_DATA.certificates;
    if (statusFilter !== 'all') filtered = filtered.filter(c => c.status === statusFilter);
    if (search) filtered = filtered.filter(c => c.cn.includes(search) || c.serial.includes(search) || c.org.includes(search));

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><svg viewBox="0 0 80 80" fill="none" stroke="#BFA89C" stroke-width="2"><circle cx="40" cy="40" r="30" stroke-dasharray="4 4" fill="none"/><path d="M30 35 L40 28 L50 35" stroke-linecap="round" stroke-linejoin="round"/><path d="M32 42 L48 42" stroke-linecap="round"/><circle cx="35" cy="38" r="2" fill="#BFA89C"/><circle cx="45" cy="38" r="2" fill="#BFA89C"/></svg><p>没有找到证书...</p></div></td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(c => `
        <tr>
            <td>${c.id}</td>
            <td>${c.cn}</td>
            <td>${c.org}</td>
            <td>${c.type}</td>
            <td><span class="hand-badge ${c.status === '有效' ? 'hand-badge-success' : c.status === '即将到期' ? 'hand-badge-warning' : 'hand-badge-danger'}">${c.status}</span></td>
            <td style="font-size:0.85rem">${c.issuedAt}</td>
            <td>
                <button class="hand-btn hand-btn-sm" onclick="showCertDetail('${c.id}')">查看</button>
                ${c.status === '有效' && PKI_DATA.currentUser.role === 'ca_admin' ? `<button class="hand-btn hand-btn-sm hand-btn-danger" onclick="showRevokeModal('${c.id}')">吊销</button>` : ''}
            </td>
        </tr>
    `).join('');
}

/* ----- 证书详情 ----- */
function showCertDetail(id) {
    const cert = PKI_DATA.certificates.find(c => c.id === id);
    if (!cert) return;
    const html = `
        <div class="detail-grid">
            <span class="detail-label">证书编号</span><span class="detail-value">${cert.id}</span>
            <span class="detail-label">序列号</span><span class="detail-value">${cert.serial}</span>
            <span class="detail-label">通用名称</span><span class="detail-value">${cert.cn}</span>
            <span class="detail-label">所属组织</span><span class="detail-value">${cert.org}</span>
            <span class="detail-label">证书类型</span><span class="detail-value">${cert.type}</span>
            <span class="detail-label">签发者</span><span class="detail-value">${cert.issuer}</span>
            <span class="detail-label">签发时间</span><span class="detail-value">${cert.issuedAt}</span>
            <span class="detail-label">到期时间</span><span class="detail-value">${cert.expiresAt}</span>
            <span class="detail-label">当前状态</span><span class="detail-value"><span class="hand-badge ${cert.status === '有效' ? 'hand-badge-success' : cert.status === '即将到期' ? 'hand-badge-warning' : 'hand-badge-danger'}">${cert.status}</span></span>
        </div>`;
    document.getElementById('modalCertBody').innerHTML = html;
    UI.showModal('modal-cert');
}

/* ----- 证书申请 ----- */
function handleCertApply(e) {
    e.preventDefault();
    const cn = document.getElementById('applyCN').value.trim();
    const org = document.getElementById('applyOrg').value.trim();
    if (!cn || !org) { UI.toast('请把信息填完整哦~', 'warning'); return; }
    const id = `CSR-${String(PKI_DATA.csrRequests.length + 1).padStart(3, '0')}`;
    PKI_DATA.csrRequests.unshift({
        id, cn, org,
        submittedAt: new Date().toISOString().slice(0, 16).replace('T', ' '),
        status: 'pending',
        currentApprover: '初审待审核'
    });
    UI.hideModal('cert-apply');
    document.getElementById('applyCN').value = '';
    document.getElementById('applyOrg').value = '';
    UI.toast(`🎉 申请已提交！编号：${id}`, 'success');
    if (document.getElementById('page-ra').classList.contains('active')) renderRARequests();
}

/* ----- RA审核页 ----- */
function renderRARequests() {
    const tbody = document.getElementById('raTableBody');
    const filter = document.getElementById('raFilter').value;
    let items = PKI_DATA.csrRequests;
    if (filter !== 'all') items = items.filter(r => r.status === filter);

    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7"><div class="hand-empty"><p>📋 没有审核记录</p></div></td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(r => `
        <tr>
            <td>${r.id}</td>
            <td>${r.cn}</td>
            <td>${r.org}</td>
            <td>${r.submittedAt}</td>
            <td><span class="hand-badge ${r.status === 'pending' ? 'hand-badge-warning' : r.status === 'first_approved' ? 'hand-badge-info' : r.status === 'approved' ? 'hand-badge-success' : 'hand-badge-danger'}">${r.status === 'pending' ? '待初审' : r.status === 'first_approved' ? '待二审' : r.status === 'approved' ? '已通过' : '已拒绝'}</span></td>
            <td style="font-size:0.85rem">${r.currentApprover || '/'}</td>
            <td>
                ${r.status === 'pending' || r.status === 'first_approved' ? `
                    <button class="hand-btn hand-btn-sm hand-btn-primary" onclick="approveCSR('${r.id}')">通过</button>
                    <button class="hand-btn hand-btn-sm hand-btn-danger" onclick="rejectCSR('${r.id}')">拒绝</button>
                ` : r.rejectReason ? `<span style="font-size:0.8rem;color:var(--color-text-light)">原因: ${r.rejectReason}</span>` : '<span style="font-size:0.8rem;color:var(--color-text-light)">已完成</span>'}
            </td>
        </tr>
    `).join('');
}

function approveCSR(id) {
    const req = PKI_DATA.csrRequests.find(r => r.id === id);
    if (!req) return;
    if (req.status === 'pending') {
        req.status = 'first_approved';
        req.firstBy = PKI_DATA.currentUser.name;
        req.currentApprover = '二审待审核';
        UI.toast(`✅ 初审通过：${id}，等待二审`, 'success');
    } else if (req.status === 'first_approved') {
        if (req.firstBy === PKI_DATA.currentUser.name) {
            UI.toast('⚠️ 初审和二审不能是同一人哦！', 'error');
            return;
        }
        req.status = 'approved';
        req.currentApprover = '已通过，待签发';
        // 签发证书
        const certId = `CERT-${String(PKI_DATA.certificates.length + 1).padStart(3, '0')}`;
        PKI_DATA.certificates.push({
            id: certId, serial: `0x${Math.random().toString(16).slice(2, 10).toUpperCase()}`,
            cn: req.cn, org: req.org, type: '用户证书', issuedAt: new Date().toISOString().slice(0, 10),
            expiresAt: new Date(Date.now() + 365*86400000).toISOString().slice(0, 10),
            status: '有效', issuer: '中间CA'
        });
        UI.toast(`🎉 二审通过，证书已签发！编号：${certId}`, 'success');
    }
    renderRARequests();
}

function rejectCSR(id) {
    const reason = prompt('✎ 填写拒绝原因：');
    if (!reason) return;
    const req = PKI_DATA.csrRequests.find(r => r.id === id);
    if (req) { req.status = 'rejected'; req.rejectReason = reason; }
    UI.toast(`已拒绝：${id}`, 'warning');
    renderRARequests();
}

/* ----- CRL吊销页 ----- */
function renderRevokedList() {
    const tbody = document.getElementById('revokedTableBody');
    if (PKI_DATA.revokedCerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>🔒 目前没有已吊销的证书</p></div></td></tr>`;
        return;
    }
    tbody.innerHTML = PKI_DATA.revokedCerts.map(r => `
        <tr>
            <td>${r.serial}</td>
            <td>${r.cn}</td>
            <td>${r.revokedAt}</td>
            <td><span class="hand-badge hand-badge-danger">${r.reason}</span></td>
            <td>${r.revokedBy}</td>
        </tr>
    `).join('');
}

function showRevokeModal(certId) {
    const cert = PKI_DATA.certificates.find(c => c.id === certId);
    if (!cert) return;
    document.getElementById('revokeCertId').value = certId;
    document.getElementById('revokeCn').value = cert.cn;
    document.getElementById('revokeSerial').value = cert.serial;
    document.getElementById('revokeReason').value = 'keyCompromise';
    UI.showModal('cert-revoke');
}

function handleRevoke(e) {
    e.preventDefault();
    const certId = document.getElementById('revokeCertId').value;
    const reason = document.getElementById('revokeReason').value;
    const reasonText = document.getElementById('revokeReason').options[document.getElementById('revokeReason').selectedIndex].text;
    const cert = PKI_DATA.certificates.find(c => c.id === certId);
    if (!cert) return;

    cert.status = '已吊销';
    PKI_DATA.revokedCerts.unshift({
        serial: cert.serial, cn: cert.cn,
        revokedAt: new Date().toISOString().slice(0, 16).replace('T', ' '),
        reason: reasonText, revokedBy: PKI_DATA.currentUser.name
    });
    UI.hideModal('cert-revoke');
    UI.toast(`🔒 证书 ${certId} 已吊销`, 'success');
    renderCertificates();
    if (document.getElementById('page-crl').classList.contains('active')) renderRevokedList();
}

function generateCRL() {
    if (PKI_DATA.revokedCerts.length === 0) { UI.toast('当前没有要吊销的证书', 'warning'); return; }
    UI.toast(`📋 CRL已生成！共 ${PKI_DATA.revokedCerts.length} 条吊销记录`, 'success');
}

/* ----- 审计日志页 ----- */
function renderAuditLogs() {
    const tbody = document.getElementById('auditTableBody');
    const filter = document.getElementById('auditFilter').value;
    const search = document.getElementById('auditSearch').value.toLowerCase();
    let items = PKI_DATA.auditLogs;
    if (filter !== 'all') items = items.filter(l => l.action === filter);
    if (search) items = items.filter(l => l.user.includes(search) || l.detail.includes(search));

    if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>📝 没有匹配的日志</p></div></td></tr>`;
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
}

/* ----- 备份页 ----- */
function renderBackups() {
    const tbody = document.getElementById('backupTableBody');
    if (PKI_DATA.backups.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="hand-empty"><p>💾 还没有备份记录</p></div></td></tr>`;
        return;
    }
    tbody.innerHTML = PKI_DATA.backups.map(b => `
        <tr>
            <td style="font-size:0.85rem">${b.name}</td>
            <td>${b.size}</td>
            <td>${b.createdAt}</td>
            <td>${b.type}</td>
            <td><span class="hand-badge hand-badge-success">${b.status}</span></td>
        </tr>
    `).join('');
}

function createBackup() {
    const now = new Date();
    const ts = now.toISOString().slice(0, 10).replace(/-/g, '') + '_' + now.toTimeString().slice(0, 6).replace(/:/g, '');
    PKI_DATA.backups.unshift({
        name: `pki_backup_${ts}.enc`, size: '2.4MB',
        createdAt: now.toISOString().slice(0, 16).replace('T', ' '),
        type: '全量备份', status: '正常'
    });
    UI.toast('💾 备份已创建！', 'success');
    renderBackups();
}

// ============================================================
// UI交互增强 - 手绘动效
// ============================================================

/* 按钮涟漪效果 */
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

/* 键盘Enter触发登录 */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && document.getElementById('loginPage').style.display !== 'none') {
        const loginBtn = document.querySelector('#loginPage .hand-btn-primary');
        if (loginBtn) loginBtn.click();
    }
});

// ============================================================
// 初始化
// ============================================================
document.addEventListener('DOMContentLoaded', function() {
    // 登录页显示/应用隐藏
    document.getElementById('loginPage').style.display = 'flex';
    document.getElementById('appContainer').style.display = 'none';

    // 绑定事件
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('menuBtn').addEventListener('click', () => {
        if (document.getElementById('sideMenu').classList.contains('open')) closeMenu();
        else openMenu();
    });
    document.getElementById('menuOverlay').addEventListener('click', closeMenu);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    document.getElementById('certApplyForm').addEventListener('submit', handleCertApply);
    document.getElementById('revokeForm').addEventListener('submit', handleRevoke);

    // 过滤器和搜索框绑定
    ['certStatusFilter', 'certSearch'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', renderCertificates);
        document.getElementById(id)?.addEventListener('change', renderCertificates);
    });
    ['raFilter'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', renderRARequests);
    });
    ['auditFilter', 'auditSearch'].forEach(id => {
        document.getElementById(id)?.addEventListener('input', renderAuditLogs);
        document.getElementById(id)?.addEventListener('change', renderAuditLogs);
    });
});
