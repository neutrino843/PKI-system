/**
 * PKI系统 - 前端API通信层
 * 封装所有后端REST API调用，替换模拟数据
 */

const API_BASE = window.location.origin;

const API = {
    async request(method, path, data = null) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
        };
        if (data) opts.body = JSON.stringify(data);
        const resp = await fetch(`${API_BASE}${path}`, opts);
        const json = await resp.json();
        if (!resp.ok) throw new Error(json.error || `HTTP ${resp.status}`);
        return json;
    },

    // --- 认证 ---
    login(username, password) {
        return API.request('POST', '/api/auth/login', { username, password });
    },
    logout() {
        return API.request('POST', '/api/auth/logout');
    },
    getMe() {
        return API.request('GET', '/api/auth/me');
    },
    getUsers() {
        return API.request('GET', '/api/auth/users');
    },

    // --- 仪表盘 ---
    getStats() {
        return API.request('GET', '/api/stats');
    },

    // --- 证书 ---
    getCertificates(status = 'all', search = '') {
        let path = `/api/certificates?status=${encodeURIComponent(status)}`;
        if (search) path += `&search=${encodeURIComponent(search)}`;
        return API.request('GET', path);
    },
    getCertDetail(serial) {
        return API.request('GET', `/api/certificates/${encodeURIComponent(serial)}`);
    },

    // --- CSR ---
    applyCert(cn, org) {
        return API.request('POST', '/api/csr/apply', { cn, org });
    },
    getCsrPending() {
        return API.request('GET', '/api/csr/pending');
    },
    getCsrApproved() {
        return API.request('GET', '/api/csr/approved');
    },
    approveFirst(csrId, note = '') {
        return API.request('POST', '/api/csr/approve-first', { csrId, note });
    },
    approveSecond(csrId, note = '') {
        return API.request('POST', '/api/csr/approve-second', { csrId, note });
    },
    rejectCsr(csrId, reason = '') {
        return API.request('POST', '/api/csr/reject', { csrId, reason });
    },

    // --- CRL/吊销 ---
    getRevoked() {
        return API.request('GET', '/api/revoked');
    },
    revokeCert(serial, cn, reason, reasonDesc) {
        return API.request('POST', '/api/revoked/revoke', { serial, cn, reason, reasonDesc });
    },
    checkRevoked(serial) {
        return API.request('GET', `/api/revoked/check/${encodeURIComponent(serial)}`);
    },
    generateCRL() {
        return API.request('POST', '/api/revoked/generate-crl');
    },
    verifyCRL() {
        return API.request('GET', '/api/revoked/verify');
    },

    // --- 审计日志 ---
    getAuditLogs(limit = 50, eventType = '', username = '') {
        let path = `/api/audit?limit=${limit}`;
        if (eventType) path += `&eventType=${encodeURIComponent(eventType)}`;
        if (username) path += `&username=${encodeURIComponent(username)}`;
        return API.request('GET', path);
    },
    verifyAudit() {
        return API.request('GET', '/api/audit/verify');
    },

    // --- 备份 ---
    getBackups() {
        return API.request('GET', '/api/backups');
    },
    createBackup(label = '') {
        return API.request('POST', '/api/backups/create', { label });
    },

    // --- 到期检查 ---
    getExpiryCheck() {
        return API.request('GET', '/api/expiry-check');
    },

    // --- 配置 ---
    getConfig() {
        return API.request('GET', '/api/config');
    },
};
