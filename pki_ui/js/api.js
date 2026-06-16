/**
 * PKI系统 - 前端API通信层
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
    register(username, password, name) {
        return API.request('POST', '/api/auth/register', { username, password, name });
    },
    promoteReviewer(username) {
        return API.request('POST', '/api/auth/promote-reviewer', { username });
    },
    demoteUser(username) {
        return API.request('POST', '/api/auth/demote-user', { username });
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
    exportPem(serial) {
        // 直接下载PEM文件
        const anchor = document.createElement('a');
        anchor.href = `${API_BASE}/api/certificates/${encodeURIComponent(serial)}/export-pem`;
        anchor.download = `cert_${serial.substring(0, 16)}.pem`;
        anchor.click();
    },
    exportCrt(serial) {
        // 下载CRT文件（Windows双击可安装）
        const anchor = document.createElement('a');
        anchor.href = `${API_BASE}/api/certificates/${encodeURIComponent(serial)}/export-crt`;
        anchor.download = `cert_${serial.substring(0, 16)}.crt`;
        anchor.click();
    },
    async exportP12(serial, password) {
        // POST请求PKCS#12导出（返回二进制）
        const resp = await fetch(`${API_BASE}/api/certificates/${encodeURIComponent(serial)}/export-p12`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ password })
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
            throw new Error(err.error || `HTTP ${resp.status}`);
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `cert_${serial.substring(0, 16)}.p12`;
        anchor.click();
        URL.revokeObjectURL(url);
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
    issueCert(csrId) {
        return API.request('POST', `/api/certificates/issue/${encodeURIComponent(csrId)}`);
    },
    getMyApplications() {
        return API.request('GET', '/api/csr/my-applications');
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

    // --- TSA 时间戳服务 ---
    getTsaStatus() {
        return API.request('GET', '/api/tsa/status');
    },
    requestTimestamp(hashValue, hashAlgorithm = 'sha256', nonce = null, requester = '') {
        const data = { hashValue, hashAlgorithm };
        if (nonce !== null) data.nonce = nonce;
        if (requester) data.requester = requester;
        return API.request('POST', '/api/tsa/timestamp', data);
    },
    verifyTimestamp(tstToken, originalHash = null, hashAlgorithm = null) {
        const data = { tstToken };
        if (originalHash) data.originalHash = originalHash;
        if (hashAlgorithm) data.hashAlgorithm = hashAlgorithm;
        return API.request('POST', '/api/tsa/verify', data);
    },
    getTsaCertificate() {
        const anchor = document.createElement('a');
        anchor.href = `${API_BASE}/api/tsa/certificate`;
        anchor.download = 'tsa_cert.pem';
        anchor.click();
    },
    syncTsaTime() {
        return API.request('POST', '/api/tsa/sync-time');
    },
    reloadTsaCert() {
        return API.request('POST', '/api/tsa/reload-cert');
    },
    getTsaRecords(limit = 100) {
        return API.request('GET', `/api/tsa/records?limit=${limit}`);
    },
    // Business scenarios
    contractSignTimestamp(contractId, contractHash, signerId, signature = '', hashAlgorithm = 'sha256') {
        return API.request('POST', '/api/tsa/scenario/contract-sign', {
            contractId, contractHash, signerId, signatureValue: signature, hashAlgorithm
        });
    },
    codeReleaseTimestamp(repoName, commitHash, branch = 'main', tag = '', committer = '') {
        return API.request('POST', '/api/tsa/scenario/code-release', {
            repoName, commitHash, branch, tag, committer
        });
    },
    archiveTimestamp(archiveId, archiveHash, archiveName = '', archiveType = '', department = '') {
        return API.request('POST', '/api/tsa/scenario/archive', {
            archiveId, archiveHash, archiveName, archiveType, department
        });
    },
    getScenarioRecords(scenarioType = '', limit = 100) {
        let path = `/api/tsa/scenario/records?limit=${limit}`;
        if (scenarioType) path += `&scenarioType=${encodeURIComponent(scenarioType)}`;
        return API.request('GET', path);
    },
};
