import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAuditLogs } from '../../api/auth';
import { Row, Badge, Empty, SectionTitle, StatCard, formatFileSize } from './AdminCommon';

export function Audit() {
    const navigate = useNavigate();
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [filterStatus, setFilterStatus] = useState('ALL');
    const [filterAction, setFilterAction] = useState('ALL');
    const [expandedLog, setExpandedLog] = useState(null);

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

    useEffect(() => {
        fetchLogs();
    }, []);

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
    const uniqueServices = new Set(logs.map(l => l.service_name)).size;

    return (
        <div className="animate-slide">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div>
                    <div className="page-title">Audit Log</div>
                    <div className="page-sub">Cryptographically chained verification events & audit trail</div>
                </div>
                <button className="btn" onClick={fetchLogs} disabled={loading} style={{ fontSize: 10, padding: '6px 14px' }}>
                    {loading ? 'Refreshing...' : 'Refresh Logs'}
                </button>
            </div>

            {/* Metric Overview */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
                <StatCard value={logs.length} label="Total Audit Events" />
                <StatCard value={unchangedCount} label="Intact Hashes" />
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
                        {['ALL', 'UNCHANGED', 'TAMPERED'].map(st => (
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
