import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAuditLogs, verifyAuditLogs, getIntegrityAlerts } from '../../api/auth';
import { Row, Badge, Empty, SectionTitle, StatCard, formatFileSize } from './AdminCommon';

export function Audit() {
    const navigate = useNavigate();
    const [logs, setLogs] = useState([]);
    const [alerts, setAlerts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [filterStatus, setFilterStatus] = useState('ALL');
    const [filterAction, setFilterAction] = useState('ALL');
    const [expandedLog, setExpandedLog] = useState(null);

    // Verification state
    const [showVerifier, setShowVerifier] = useState(false);
    const [showAlerts, setShowAlerts] = useState(false);
    const [verifyScope, setVerifyScope] = useState('case');
    const [verifyTargetId, setVerifyTargetId] = useState('');
    const [autoRestore, setAutoRestore] = useState(true);
    const [verifying, setVerifying] = useState(false);
    const [verifyResult, setVerifyResult] = useState(null);
    const [verifyError, setVerifyError] = useState('');

    const fetchLogs = async () => {
        setLoading(true);
        setError('');
        try {
            const data = await getAuditLogs({});
            setLogs(data || []);
        } catch (err) {
            setError(err.message || 'Failed to load audit logs');
            setLogs([]);
        } finally {
            setLoading(false);
        }
    };

    const fetchAlerts = async () => {
        try {
            const data = await getIntegrityAlerts({ limit: 10 });
            setAlerts(data || []);
        } catch (err) {
            console.error('Failed to load integrity alerts:', err);
        }
    };

    useEffect(() => {
        fetchLogs();
        fetchAlerts();
    }, []);

    const handleRunVerification = async (scopeOverride, idOverride) => {
        const scope = scopeOverride || verifyScope;
        const id = idOverride || verifyTargetId;
        if (!id.trim()) {
            setVerifyError('Target ID is required');
            return;
        }

        setVerifying(true);
        setVerifyError('');
        setVerifyResult(null);

        try {
            const res = await verifyAuditLogs({
                scope,
                id: id.trim(),
                autoRestore
            });
            setVerifyResult(res);
            // Refresh logs and alerts if autoRestore restored records
            if (res.restored || res.modified) {
                fetchLogs();
                fetchAlerts();
            }
        } catch (err) {
            setVerifyError(err.message || 'Verification request failed');
        } finally {
            setVerifying(false);
        }
    };

    const openVerifierForTarget = (scope, id) => {
        setVerifyScope(scope);
        setVerifyTargetId(id);
        setShowVerifier(true);
        setVerifyResult(null);
        setVerifyError('');
    };

    const filteredLogs = logs.filter(log => {
        if (filterStatus !== 'ALL' && log.status?.toUpperCase() !== filterStatus) return false;
        if (filterAction !== 'ALL' && log.action !== filterAction) return false;
        if (searchTerm.trim()) {
            const term = searchTerm.toLowerCase();
            const evName = (log.evidence_name || log.details?.file_name || '').toLowerCase();
            const caseTitle = (log.case_title || log.details?.case_title || '').toLowerCase();
            const userName = (log.user_name || log.details?.user_name || '').toLowerCase();
            const serviceName = (log.service_name || '').toLowerCase();
            const evId = (log.evidence_public_id || '').toLowerCase();
            const currentHash = (log.current_hash || '').toLowerCase();
            const prevHash = (log.previous_hash || '').toLowerCase();
            const publicId = (log.public_id || '').toLowerCase();
            const reqId = (log.request_id || '').toLowerCase();
            const ip = (log.ip_address || '').toLowerCase();

            const match = evName.includes(term) ||
                caseTitle.includes(term) ||
                userName.includes(term) ||
                serviceName.includes(term) ||
                evId.includes(term) ||
                currentHash.includes(term) ||
                prevHash.includes(term) ||
                publicId.includes(term) ||
                reqId.includes(term) ||
                ip.includes(term);
            if (!match) return false;
        }
        return true;
    });

    const tamperedCount = logs.filter(l => l.status?.toUpperCase() === 'TAMPERED').length;
    const unchangedCount = logs.filter(l => l.status?.toUpperCase() === 'UNCHANGED').length;
    const restoredCount = logs.filter(l => l.status?.toUpperCase() === 'RESTORED').length;
    const uniqueServices = new Set(logs.map(l => l.service_name)).size;

    return (
        <div className="animate-slide">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div>
                    <div className="page-title">Audit Log</div>
                    <div className="page-sub">Cryptographically chained verification events & audit trail</div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <button
                        className="btn"
                        onClick={() => {
                            setShowVerifier(!showVerifier);
                            if (logs.length > 0 && !verifyTargetId) {
                                setVerifyTargetId(logs[0].case_public_id || logs[0].evidence_public_id || '');
                            }
                        }}
                        style={{
                            fontSize: 10,
                            padding: '6px 14px',
                            background: showVerifier ? 'rgba(0,200,120,0.15)' : 'transparent',
                            borderColor: showVerifier ? '#00c878' : 'var(--rule2)',
                            color: showVerifier ? '#00c878' : 'var(--ink)'
                        }}
                    >
                        🛡️ {showVerifier ? 'Close Verifier' : 'Verify Ledger Integrity'}
                    </button>
                    {alerts.length > 0 && (
                        <button
                            className="btn"
                            onClick={() => setShowAlerts(!showAlerts)}
                            style={{
                                fontSize: 10,
                                padding: '6px 14px',
                                background: showAlerts ? 'rgba(255,170,0,0.15)' : 'transparent',
                                borderColor: showAlerts ? '#ffaa00' : 'var(--rule2)',
                                color: showAlerts ? '#ffaa00' : 'var(--ink)'
                            }}
                        >
                            🔔 Alerts ({alerts.length})
                        </button>
                    )}
                    <button className="btn" onClick={() => { fetchLogs(); fetchAlerts(); }} disabled={loading} style={{ fontSize: 10, padding: '6px 14px' }}>
                        {loading ? 'Refreshing...' : 'Refresh Logs'}
                    </button>
                </div>
            </div>

            {/* Verification / Repair Panel */}
            {showVerifier && (
                <div className="card" style={{ marginBottom: 20, border: '1px solid #00c878', background: 'rgba(0,200,120,0.03)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                        <div style={{ fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 600, color: '#00c878', display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span>🛡️</span> MULTI-LEVEL LOG INTEGRITY VERIFIER & S3 AUTO-RESTORATION
                        </div>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>
                            SHA-256 Chained Hash Check &rarr; S3 Batch Manifest Cross-Verification &rarr; Postgres Auto-Repair
                        </span>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr auto', gap: 12, alignItems: 'center', marginBottom: 14 }}>
                        <div style={{ display: 'flex', gap: 4 }}>
                            {['evidence', 'case', 'org'].map(sc => (
                                <button
                                    key={sc}
                                    type="button"
                                    onClick={() => setVerifyScope(sc)}
                                    className="btn"
                                    style={{
                                        flex: 1,
                                        fontSize: 9,
                                        padding: '6px 4px',
                                        textTransform: 'uppercase',
                                        background: verifyScope === sc ? 'rgba(0,200,120,0.2)' : 'transparent',
                                        borderColor: verifyScope === sc ? '#00c878' : 'var(--rule2)',
                                        color: verifyScope === sc ? '#00c878' : 'var(--ink3)'
                                    }}
                                >
                                    {sc}
                                </button>
                            ))}
                        </div>

                        <div>
                            <input
                                type="text"
                                placeholder={`Enter ${verifyScope.toUpperCase()} public UUID or internal ID...`}
                                value={verifyTargetId}
                                onChange={(e) => setVerifyTargetId(e.target.value)}
                                style={{
                                    width: '100%',
                                    padding: '7px 10px',
                                    background: 'var(--card)',
                                    border: '1px solid var(--rule2)',
                                    color: 'var(--ink)',
                                    fontFamily: 'var(--mono)',
                                    fontSize: 11
                                }}
                            />
                        </div>

                        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink2)' }}>
                                <input
                                    type="checkbox"
                                    checked={autoRestore}
                                    onChange={(e) => setAutoRestore(e.target.checked)}
                                    style={{ cursor: 'pointer' }}
                                />
                                Auto-Restore from S3
                            </label>

                            <button
                                type="button"
                                onClick={() => handleRunVerification()}
                                disabled={verifying || !verifyTargetId.trim()}
                                className="btn"
                                style={{
                                    fontSize: 10,
                                    padding: '7px 16px',
                                    background: '#00c878',
                                    color: '#000',
                                    fontWeight: 600,
                                    cursor: verifying ? 'wait' : 'pointer'
                                }}
                            >
                                {verifying ? 'Verifying...' : 'Run Verification'}
                            </button>
                        </div>
                    </div>

                    {verifyError && (
                        <div style={{ padding: '8px 12px', background: 'rgba(255,60,60,0.1)', border: '1px solid #ff4444', color: '#ff6666', fontFamily: 'var(--mono)', fontSize: 10, marginBottom: 12 }}>
                            {verifyError.toUpperCase()}
                        </div>
                    )}

                    {verifyResult && (
                        <div style={{ padding: 14, background: 'rgba(0,0,0,0.3)', border: '1px solid var(--rule2)', borderRadius: 2 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10, borderBottom: '1px solid var(--rule2)', paddingBottom: 8 }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                    <Badge status={verifyResult.status} />
                                    <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink)' }}>
                                        {verifyResult.message}
                                    </span>
                                </div>
                                <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>
                                    Verified at: {new Date(verifyResult.verified_at).toLocaleTimeString()}
                                </span>
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8, marginBottom: 12 }}>
                                <div style={{ background: 'rgba(0,0,0,0.2)', padding: 8 }}>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)' }}>SCOPE & ID</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{verifyResult.scope.toUpperCase()}: {verifyResult.target_id.slice(0, 12)}...</div>
                                </div>
                                <div style={{ background: 'rgba(0,0,0,0.2)', padding: 8 }}>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)' }}>EVIDENCES</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink)' }}>{verifyResult.evidences_checked} Checked</div>
                                </div>
                                <div style={{ background: 'rgba(0,0,0,0.2)', padding: 8 }}>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)' }}>LOGS CHECKED</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--ink)' }}>{verifyResult.logs_checked} Records</div>
                                </div>
                                <div style={{ background: 'rgba(0,0,0,0.2)', padding: 8 }}>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)' }}>TAMPERED ROWS</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: verifyResult.tampered_count > 0 ? '#ff4444' : '#00c878' }}>
                                        {verifyResult.tampered_count} Detected
                                    </div>
                                </div>
                                <div style={{ background: 'rgba(0,0,0,0.2)', padding: 8 }}>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)' }}>RESTORED FROM S3</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: verifyResult.restored_count > 0 ? '#00b4ff' : 'var(--ink3)' }}>
                                        {verifyResult.restored_count} Restored
                                    </div>
                                </div>
                            </div>

                            {verifyResult.issues && verifyResult.issues.length > 0 && (
                                <div style={{ marginTop: 10 }}>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)', marginBottom: 6, textTransform: 'uppercase' }}>
                                        Discrepancy Details & Restoration Actions ({verifyResult.issues.length}):
                                    </div>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
                                        {verifyResult.issues.map((iss, idx) => (
                                            <div key={idx} style={{ padding: '6px 10px', background: 'rgba(0,0,0,0.4)', borderLeft: `3px solid ${iss.restored ? '#00b4ff' : '#ff4444'}`, fontFamily: 'var(--mono)', fontSize: 9 }}>
                                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                                                    <span style={{ color: iss.restored ? '#00b4ff' : '#ff6666', fontWeight: 600 }}>
                                                        {iss.issue_type} {iss.restored ? '• RESTORED' : ''}
                                                    </span>
                                                    <span style={{ color: 'var(--ink3)' }}>
                                                        Req: {iss.request_id || '-'} | Log ID: {iss.log_id || '-'}
                                                    </span>
                                                </div>
                                                <div style={{ color: 'var(--ink)', fontSize: 10 }}>{iss.message}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Integrity Alerts Section */}
            {showAlerts && alerts.length > 0 && (
                <div className="card" style={{ marginBottom: 20, border: '1px solid #ffaa00', background: 'rgba(255,170,0,0.03)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                        <SectionTitle>Integrity Alerts Log ({alerts.length})</SectionTitle>
                        <button className="btn" onClick={() => setShowAlerts(false)} style={{ fontSize: 9, padding: '2px 8px' }}>Close</button>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {alerts.map(al => (
                            <div key={al.public_id} style={{ padding: '8px 12px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--rule2)' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        <Badge status={al.status} />
                                        <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink)' }}>
                                            Scope: {al.scope?.toUpperCase()} | Target: {al.target_id}
                                        </span>
                                    </div>
                                    <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>
                                        {new Date(al.created_at).toLocaleString()}
                                    </span>
                                </div>
                                <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>
                                    Tampered Count: <span style={{ color: '#ff4444' }}>{al.tampered_count}</span> | Restored Count: <span style={{ color: '#00b4ff' }}>{al.restored_count}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Metric Overview */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 20 }}>
                <StatCard value={logs.length} label="Total Audit Events" />
                <StatCard value={unchangedCount} label="Intact Hashes" />
                <StatCard value={restoredCount} label="Restored Events" />
                <StatCard value={tamperedCount} label="Tampered Events" />
                <StatCard value={uniqueServices} label="Connected Services" />
            </div>

            {/* Filter Bar */}
            <div className="card" style={{ marginBottom: 16, padding: '12px 16px' }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: 220 }}>
                        <input
                            type="text"
                            placeholder="Search by evidence name, case, user, hash, ID..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            style={{
                                width: '100%',
                                padding: '6px 10px',
                                background: 'var(--card)',
                                border: '1px solid var(--rule2)',
                                color: 'var(--ink)',
                                fontFamily: 'var(--mono)',
                                fontSize: 11
                            }}
                        />
                    </div>

                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>STATUS:</span>
                        {['ALL', 'UNCHANGED', 'RESTORED', 'TAMPERED'].map(st => (
                            <button
                                key={st}
                                onClick={() => setFilterStatus(st)}
                                className="btn"
                                style={{
                                    fontSize: 9,
                                    padding: '4px 8px',
                                    background: filterStatus === st ? 'rgba(255,255,255,0.12)' : 'transparent',
                                    border: `1px solid ${filterStatus === st ? 'var(--ink)' : 'var(--rule2)'}`
                                }}
                            >
                                {st}
                            </button>
                        ))}
                    </div>

                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>ACTION:</span>
                        {['ALL', 'UPLOAD', 'VIEW', 'VERIFY', 'DOWNLOAD'].map(act => (
                            <button
                                key={act}
                                onClick={() => setFilterAction(act)}
                                className="btn"
                                style={{
                                    fontSize: 9,
                                    padding: '4px 8px',
                                    background: filterAction === act ? 'rgba(255,255,255,0.12)' : 'transparent',
                                    border: `1px solid ${filterAction === act ? 'var(--ink)' : 'var(--rule2)'}`
                                }}
                            >
                                {act}
                            </button>
                        ))}
                    </div>

                    {searchTerm && (
                        <button className="btn" onClick={() => setSearchTerm('')} style={{ fontSize: 10, padding: '6px 12px' }}>
                            Clear
                        </button>
                    )}
                </div>
            </div>

            {error && (
                <div style={{ padding: '10px 14px', background: 'rgba(255,60,60,0.1)', border: '1px solid #ff4444', color: '#ff6666', fontFamily: 'var(--mono)', fontSize: 10, marginBottom: 16 }}>
                    {error.toUpperCase()}
                </div>
            )}

            {/* Audit Logs Table */}
            <div className="card">
                <SectionTitle>Audit Chain ({filteredLogs.length} Records)</SectionTitle>

                {loading && <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)', padding: 24, textAlign: 'center' }}>VERIFYING LEDGER INTEGRITY & LOADING AUDIT LOGS...</div>}

                {!loading && filteredLogs.length === 0 && (
                    <Empty>No audit log records found matching the criteria.</Empty>
                )}

                {!loading && filteredLogs.length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '140px 90px 90px 1fr 140px 140px 120px', gap: 10, padding: '8px 0', borderBottom: '1px solid var(--rule2)', fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)', textTransform: 'uppercase' }}>
                            <div>Timestamp</div>
                            <div>Status</div>
                            <div>Action</div>
                            <div>Hash Chain (Prev &rarr; Current)</div>
                            <div>Service & Origin</div>
                            <div>Evidence & Case</div>
                            <div style={{ textAlign: 'right' }}>Actions</div>
                        </div>

                        {filteredLogs.map(log => {
                            const isExpanded = expandedLog === log.public_id;
                            const isTampered = log.status?.toUpperCase() === 'TAMPERED';
                            const evDisplayName = log.evidence_name || (log.details?.file_name) || (log.evidence_public_id ? `EVID: ${log.evidence_public_id.slice(0, 8)}...` : 'Evidence Item');
                            const caseDisplayName = log.case_title || (log.details?.case_title) || (log.case_public_id ? `Case: ${log.case_public_id.slice(0, 8)}...` : '');
                            const actorName = log.user_name || (log.details?.user_name) || '';

                            return (
                                <div key={log.public_id || log.created_at} style={{ borderBottom: '1px solid var(--rule2)', padding: '10px 0' }}>
                                    <div style={{ display: 'grid', gridTemplateColumns: '140px 90px 90px 1fr 140px 140px 120px', gap: 10, alignItems: 'center' }}>
                                        <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)' }}>
                                            {new Date(log.created_at).toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'medium' })}
                                        </div>
                                        <div>
                                            <Badge status={log.status?.toUpperCase() || 'UNCHANGED'} />
                                        </div>
                                        <div>
                                            <Badge status={log.action} />
                                        </div>
                                        <div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)', fontSize: 9 }}>
                                                <span style={{ color: log.previous_hash ? 'var(--ink3)' : '#555' }} title={`Previous Hash: ${log.previous_hash || 'GENESIS'}`}>
                                                    {log.previous_hash ? `${log.previous_hash.slice(0, 8)}...` : 'GENESIS'}
                                                </span>
                                                <span style={{ color: 'var(--ink3)' }}>&rarr;</span>
                                                <span style={{ color: isTampered ? '#ff4444' : '#00c878', fontWeight: 600 }} title={`Current Hash: ${log.current_hash}`}>
                                                    {log.current_hash ? `${log.current_hash.slice(0, 10)}...` : '-'}
                                                </span>
                                            </div>
                                        </div>
                                        <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>
                                            <div style={{ color: 'var(--ink)' }}>{log.service_name || 'unknown'}</div>
                                            <div style={{ fontSize: 8, color: '#777' }}>{log.ip_address || '-'}</div>
                                        </div>
                                        <div style={{ fontFamily: 'var(--mono)', fontSize: 9 }}>
                                            <div style={{ color: 'var(--accent)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={evDisplayName}>
                                                {evDisplayName}
                                            </div>
                                            {caseDisplayName && (
                                                <div style={{ color: 'var(--ink3)', fontSize: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={caseDisplayName}>
                                                    {caseDisplayName}
                                                </div>
                                            )}
                                        </div>
                                        <div style={{ textAlign: 'right', display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                                            <button
                                                className="btn"
                                                onClick={() => openVerifierForTarget('evidence', log.evidence_public_id || String(log.evidence_id))}
                                                style={{ fontSize: 8, padding: '2px 6px', color: '#00c878', borderColor: 'rgba(0,200,120,0.4)' }}
                                                title="Verify integrity of this evidence chain"
                                            >
                                                Verify
                                            </button>
                                            <button
                                                className="btn"
                                                onClick={() => navigate(`/admin/audit-log/${log.public_id}`)}
                                                style={{ fontSize: 8, padding: '2px 8px', color: 'var(--accent)' }}
                                            >
                                                Details &rarr;
                                            </button>
                                            <button
                                                className="btn"
                                                onClick={() => setExpandedLog(isExpanded ? null : log.public_id)}
                                                style={{ fontSize: 8, padding: '2px 6px' }}
                                            >
                                                {isExpanded ? 'Hide' : 'Quick'}
                                            </button>
                                        </div>
                                    </div>

                                    {isExpanded && (
                                        <div style={{ marginTop: 10, padding: '10px 14px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--rule2)', borderRadius: 2 }}>
                                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginBottom: 8, fontFamily: 'var(--mono)', fontSize: 10 }}>
                                                <div>
                                                    <span style={{ color: 'var(--ink3)' }}>PUBLIC AUDIT ID: </span>
                                                    <span style={{ color: 'var(--ink)' }}>{log.public_id}</span>
                                                </div>
                                                <div>
                                                    <span style={{ color: 'var(--ink3)' }}>REQUEST ID: </span>
                                                    <span style={{ color: 'var(--ink)' }}>{log.request_id || '-'}</span>
                                                </div>
                                                <div>
                                                    <span style={{ color: 'var(--ink3)' }}>PREVIOUS HASH: </span>
                                                    <span style={{ color: 'var(--ink)', wordBreak: 'break-all' }}>{log.previous_hash || 'None (Genesis Record)'}</span>
                                                </div>
                                                <div>
                                                    <span style={{ color: 'var(--ink3)' }}>CURRENT HASH: </span>
                                                    <span style={{ color: isTampered ? '#ff4444' : '#00c878', wordBreak: 'break-all' }}>{log.current_hash}</span>
                                                </div>
                                            </div>
                                            {log.details && Object.keys(log.details).length > 0 && (
                                                <div style={{ marginTop: 8 }}>
                                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)', marginBottom: 4 }}>EXTRA AUDIT DETAILS:</div>
                                                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8, fontFamily: 'var(--mono)', fontSize: 10, background: 'rgba(0,0,0,0.2)', padding: 8 }}>
                                                        {log.details.file_name && <div><span style={{ color: 'var(--ink3)' }}>FILE: </span>{log.details.file_name}</div>}
                                                        {log.details.file_size && <div><span style={{ color: 'var(--ink3)' }}>SIZE: </span>{formatFileSize(log.details.file_size)}</div>}
                                                        {log.details.case_title && <div><span style={{ color: 'var(--ink3)' }}>CASE: </span>{log.details.case_title}</div>}
                                                        {log.details.user_name && <div><span style={{ color: 'var(--ink3)' }}>USER: </span>{log.details.user_name}</div>}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>
        </div>
    );
}
