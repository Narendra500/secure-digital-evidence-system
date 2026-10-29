import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { getCaseUsers, getEvidence, uploadEvidence, downloadEvidence, verifyEvidence, revertEvidence, exportCaseEvidenceZip, createCase, getOrgDepartments, verifyAuditLogs } from '../../api/auth';
import { Row, Badge, Empty, SectionTitle, computeSHA256, formatFileSize, StatCard } from './AdminCommon';
import { Field, ErrorBanner, SuccessBanner } from '../auth/FormParts';

const EVIDENCE_TYPES = ['Document', 'Image', 'Video', 'Audio', 'Archive', 'Other'];

export function EvidenceSection({ caseId }) {
    const fileRef = useRef();
    const [dragging, setDragging] = useState(false);
    const [file, setFile] = useState(null);
    const [hash, setHash] = useState('');
    const [hashing, setHashing] = useState(false);
    const [form, setForm] = useState({ type: 'Document', description: '' });
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [uploading, setUploading] = useState(false);
    const [verifying, setVerifying] = useState(null);
    const [reverting, setReverting] = useState(null);
    const [exportingZip, setExportingZip] = useState(false);
    const [verifyingLogs, setVerifyingLogs] = useState(false);
    const [evidence, setEvidence] = useState([]);
    const [loading, setLoading] = useState(true);

    const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

    const loadEvidence = async () => {
        setLoading(true);
        try {
            const list = await getEvidence(caseId);
            if (Array.isArray(list)) {
                setEvidence(list)
                return;
            }
            setEvidence([]);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (caseId) {
            loadEvidence();
            setFile(null);
            setHash('');
            setError('');
            setSuccess('');
        }
    }, [caseId]);

    const handleFile = async (f) => {
        setFile(f); setHash(''); setSuccess(''); setHashing(true);
        try { const h = await computeSHA256(f); setHash(h); }
        finally { setHashing(false); }
    };

    const handleDrop = (e) => {
        e.preventDefault(); setDragging(false);
        const f = e.dataTransfer.files[0];
        if (f) handleFile(f);
    };

    const submit = async (e) => {
        e.preventDefault();
        if (!file) { setError('NO FILE SELECTED'); return; }
        setError(''); setSuccess(''); setUploading(true);
        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('case_id', caseId);
            formData.append('type', form.type);
            formData.append('description', form.description);

            await uploadEvidence(formData);
            setSuccess(`EVIDENCE "${file.name}" UPLOADED SUCCESSFULLY`);
            setFile(null); setHash('');
            setForm(f => ({ ...f, description: '' }));
            await loadEvidence();
        } catch (err) {
            setError(err.message.toUpperCase());
        } finally { setUploading(false); }
    };

    const recheck = async (id, publicId) => {
        setVerifying(id);
        setError('');
        try {
            const res = await verifyEvidence(publicId || id);
            const isValid = res.status.toUpperCase() === 'VALID';
            setEvidence(ev => ev.map(e => e.id === id
                ? { ...e, status: isValid ? 'VALID' : 'TAMPERED', integrityStatus: isValid ? 'VERIFIED' : 'TAMPERED', current_hash: res.computed_hash || e.current_hash, lastChecked: new Date().toISOString() }
                : e
            ));
            if (isValid) {
                setSuccess('EVIDENCE INTEGRITY VERIFIED (SHA256 MATCH)');
            } else {
                setError(`EVIDENCE TAMPERED: ${res.message || 'HASH MISMATCH DETECTED'}`);
            }
        } catch (err) {
            setError('VERIFICATION FAILED: ' + (err.message || '').toUpperCase());
        } finally {
            setVerifying(null);
        }
    };

    const handleRevert = async (ev) => {
        const id = ev.public_id || ev.id;
        const confirmRevert = window.confirm(
            `Are you sure you want to revert "${ev.file_name}" to its previous known-good version? This will restore the original file in storage and record a REVERT event in the audit trail.`
        );
        if (!confirmRevert) return;

        setReverting(ev.id);
        setError('');
        setSuccess('');
        try {
            const res = await revertEvidence(id);
            setSuccess(`EVIDENCE "${ev.file_name}" SUCCESSFULLY REVERTED TO ORIGINAL VERSION (${res.restored_hash || ''})`);
            // Refresh evidence list
            const updated = await getEvidence(caseId);
            setEvidence(updated || []);
        } catch (err) {
            setError('REVERT FAILED: ' + (err.message || '').toUpperCase());
        } finally {
            setReverting(null);
        }
    };

    const handleDownload = async (ev) => {
        try {
            const blob = await downloadEvidence(ev.public_id);
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', ev.file_name);
            document.body.appendChild(link);
            link.click();
            link.parentNode.removeChild(link);
            window.URL.revokeObjectURL(url);
        } catch (err) {
            setError('DOWNLOAD FAILED: ' + err.message.toUpperCase());
        }
    };

    const handleExportZip = async () => {
        if (!caseId || evidence.length === 0) return;
        setExportingZip(true);
        setError('');
        try {
            const blob = await exportCaseEvidenceZip(caseId);
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `case_${caseId}_evidence.zip`);
            document.body.appendChild(link);
            link.click();
            link.parentNode.removeChild(link);
            window.URL.revokeObjectURL(url);
            setSuccess('CASE EVIDENCE ZIP PACKAGE DOWNLOADED SUCCESSFULLY');
        } catch (err) {
            setError('EXPORT FAILED: ' + (err.message || '').toUpperCase());
        } finally {
            setExportingZip(false);
        }
    };

    const handleVerifyCaseLogs = async () => {
        if (!caseId) return;
        setVerifyingLogs(true);
        setError('');
        try {
            const res = await verifyAuditLogs({ scope: 'case', id: caseId, autoRestore: true });
            if (res.status === 'VALID') {
                setSuccess(`CASE LOG INTEGRITY VERIFIED: All ${res.logs_checked} audit log records match cryptographic chains and S3 manifests.`);
            } else if (res.status === 'TAMPERED_AND_RESTORED') {
                setSuccess(`TAMPERING DETECTED & REPAIRED: Restored ${res.restored_count} log records from authoritative S3 manifests.`);
                loadEvidence();
            } else {
                setError(`INTEGRITY WARNING: ${res.tampered_count} log records showed tampering.`);
            }
        } catch (err) {
            setError('VERIFICATION FAILED: ' + (err.message || '').toUpperCase());
        } finally {
            setVerifyingLogs(false);
        }
    };

    return (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16, marginTop: 12 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)' }}>
                        {evidence.length} EVIDENCE ITEM{evidence.length !== 1 ? 'S' : ''} FOR THIS CASE
                    </span>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <button
                            type="button"
                            onClick={handleVerifyCaseLogs}
                            disabled={verifyingLogs}
                            className="btn btn-secondary btn-sm"
                            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, padding: '4px 10px', cursor: 'pointer', color: '#00c878', borderColor: 'rgba(0,200,120,0.4)' }}
                        >
                            {verifyingLogs ? 'VERIFYING...' : '🛡️ VERIFY CASE LOGS'}
                        </button>
                        {evidence.length > 0 && (
                            <button
                                type="button"
                                onClick={handleExportZip}
                                disabled={exportingZip}
                                className="btn btn-secondary btn-sm"
                                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, padding: '4px 10px', cursor: 'pointer' }}
                            >
                                {exportingZip ? 'EXPORTING...' : '📦 EXPORT ALL (.ZIP)'}
                            </button>
                        )}
                    </div>
                </div>
                <div className="card" style={{ padding: 0, maxHeight: 400, overflowY: 'auto' }}>
                    {loading ? (
                        <Empty>Loading evidence...</Empty>
                    ) : evidence.length === 0 ? (
                        <Empty>No evidence uploaded yet. Use the form to upload →</Empty>
                    ) : (
                        evidence.map(ev => {
                            const isTampered = (ev.status || '').toUpperCase() === 'TAMPERED';
                            return (
                                <div key={ev.id} style={{ padding: '14px 20px', borderBottom: '1px solid var(--rule2)' }}>
                                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                                        <div style={{ width: 36, height: 36, background: 'var(--rule2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)', textTransform: 'uppercase' }}>
                                            {ev.file_name.split('.').pop()?.slice(0, 3) || 'BIN'}
                                        </div>
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.file_name}</div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                                                <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>{formatFileSize(ev.file_size)}</span>
                                                <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>{new Date(ev.uploaded_at).toLocaleDateString('en-IN')}</span>
                                                <Badge status={ev.status || 'UNKNOWN'} />
                                            </div>
                                            <div style={{ marginTop: 8, padding: '6px 10px', background: 'var(--rule2)' }}>
                                                <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)', marginBottom: 3, letterSpacing: '0.08em' }}>SHA-256</div>
                                                <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: isTampered ? '#ff4444' : 'var(--ink2)', wordBreak: 'break-all', lineHeight: 1.5 }}>{ev.current_hash}</div>
                                            </div>
                                            {ev.lastChecked && <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)', marginTop: 6 }}>Last verified: {new Date(ev.lastChecked).toLocaleString('en-IN')}</div>}
                                        </div>
                                        <div style={{ flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
                                            <button className="btn" style={{ fontSize: 9, padding: '4px 10px', whiteSpace: 'nowrap' }} onClick={() => handleDownload(ev)}>
                                                Download
                                            </button>
                                            <button className="btn" style={{ fontSize: 9, padding: '4px 10px', whiteSpace: 'nowrap' }} onClick={() => recheck(ev.id, ev.public_id)} disabled={verifying === ev.id}>
                                                {verifying === ev.id ? 'Checking...' : 'Verify'}
                                            </button>
                                            {isTampered && (
                                                <button
                                                    className="btn"
                                                    style={{ fontSize: 9, padding: '4px 10px', whiteSpace: 'nowrap', background: '#dc2626', color: '#fff', borderColor: '#b91c1c', fontWeight: 600 }}
                                                    onClick={() => handleRevert(ev)}
                                                    disabled={reverting === ev.id}
                                                >
                                                    {reverting === ev.id ? 'Reverting...' : 'Revert File'}
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            );
                        })
                    )}
                </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="card">
                    <SectionTitle>Upload Evidence</SectionTitle>
                    <ErrorBanner message={error} />
                    <SuccessBanner message={success} />
                    <form onSubmit={submit}>
                        <div
                            style={{ border: `1px dashed ${dragging ? 'var(--ink2)' : 'var(--rule)'}`, padding: '24px 16px', textAlign: 'center', marginBottom: 14, cursor: 'pointer', background: dragging ? 'rgba(255,255,255,0.02)' : 'transparent', transition: 'all 0.15s ease' }}
                            onDragOver={e => { e.preventDefault(); setDragging(true); }}
                            onDragLeave={() => setDragging(false)}
                            onDrop={handleDrop}
                            onClick={() => fileRef.current.click()}
                        >
                            <input ref={fileRef} type="file" style={{ display: 'none' }} onChange={e => e.target.files[0] && handleFile(e.target.files[0])} />
                            {file ? (
                                <div>
                                    <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4, wordBreak: 'break-all' }}>{file.name}</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>{(file.size / 1024).toFixed(1)} KB</div>
                                </div>
                            ) : (
                                <div>
                                    <div style={{ fontSize: 12, color: 'var(--ink2)', marginBottom: 4 }}>Drop file or click to browse</div>
                                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--ink3)' }}>Any file type accepted</div>
                                </div>
                            )}
                        </div>
                        {(hashing || hash) && (
                            <div style={{ padding: '8px 10px', background: 'var(--rule2)', marginBottom: 14 }}>
                                <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--ink3)', marginBottom: 4, letterSpacing: '0.08em' }}>SHA-256 HASH</div>
                                {hashing
                                    ? <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)' }}>Computing...</div>
                                    : <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: '#00c878', wordBreak: 'break-all', lineHeight: 1.5 }}>{hash}</div>}
                            </div>
                        )}
                        <Field label="Evidence Type">
                            <select className="select" value={form.type} onChange={set('type')}>
                                {EVIDENCE_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                            </select>
                        </Field>
                        <Field label="Description">
                            <textarea className="input" value={form.description} onChange={set('description')} placeholder="Optional description..." style={{ height: 64, resize: 'none' }} />
                        </Field>
                        <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={uploading || hashing}>
                            {uploading ? 'Uploading...' : 'Upload Evidence'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}

export function Cases({ cases = [], onRefresh }) {
    const navigate = useNavigate();
    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState('ALL');
    const [departments, setDepartments] = useState([]);

    // Create Case Form State
    const [form, setForm] = useState({ title: '', description: '', priority: 'medium', dept_id: '' });
    const [creating, setCreating] = useState(false);
    const [createError, setCreateError] = useState('');
    const [createSuccess, setCreateSuccess] = useState('');

    useEffect(() => {
        getOrgDepartments()
            .then(res => {
                const list = Array.isArray(res) ? res : [];
                setDepartments(list);
                if (list.length > 0 && !form.dept_id) {
                    setForm(f => ({ ...f, dept_id: list[0].public_id }));
                }
            })
            .catch(() => setDepartments([]));
    }, []);

    const handleCreate = async (e) => {
        e.preventDefault();
        if (!form.title.trim()) {
            setCreateError('CASE TITLE IS REQUIRED');
            return;
        }
        if (!form.dept_id) {
            setCreateError('PLEASE SELECT A DEPARTMENT');
            return;
        }
        setCreating(true);
        setCreateError('');
        setCreateSuccess('');
        try {
            await createCase(form);
            setCreateSuccess(`CASE "${form.title}" CREATED SUCCESSFULLY`);
            setForm({ title: '', description: '', priority: 'medium', dept_id: departments[0]?.public_id || '' });
            if (onRefresh) onRefresh();
        } catch (err) {
            setCreateError(err.message?.toUpperCase() || 'FAILED TO CREATE CASE');
        } finally {
            setCreating(false);
        }
    };

    const filteredCases = cases.filter(c => {
        if (statusFilter !== 'ALL' && c.status?.toUpperCase() !== statusFilter) return false;
        if (searchTerm.trim()) {
            const term = searchTerm.toLowerCase();
            const titleMatch = c.title?.toLowerCase().includes(term);
            const idMatch = c.public_id?.toLowerCase().includes(term);
            const descMatch = c.description?.toLowerCase().includes(term);
            if (!titleMatch && !idMatch && !descMatch) return false;
        }
        return true;
    });

    return (
        <div className="animate-slide">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
                <div>
                    <div className="page-title">Case Management</div>
                    <div className="page-sub">View, create, and manage digital forensic cases</div>
                </div>
                {onRefresh && (
                    <button className="btn" onClick={onRefresh} style={{ fontSize: 10, padding: '6px 14px' }}>
                        Refresh Cases
                    </button>
                )}
            </div>

            {/* Filter and Search Bar */}
            <div className="card" style={{ marginBottom: 16, padding: '12px 16px' }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: 220 }}>
                        <input
                            type="text"
                            placeholder="Search cases by title, ID or description..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="input"
                            style={{ height: 32, fontSize: 11, fontFamily: 'var(--mono)' }}
                        />
                    </div>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {['ALL', 'OPEN', 'IN_PROGRESS', 'CLOSED', 'ARCHIVED'].map(st => (
                            <button
                                key={st}
                                onClick={() => setStatusFilter(st)}
                                className="btn"
                                style={{
                                    fontSize: 9,
                                    padding: '4px 8px',
                                    background: statusFilter === st ? 'rgba(255,255,255,0.12)' : 'transparent',
                                    border: `1px solid ${statusFilter === st ? 'var(--ink)' : 'var(--rule2)'}`
                                }}
                            >
                                {st}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16 }}>
                {/* Cases List */}
                <div className="card" style={{ padding: 0 }}>
                    <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--rule2)' }}>
                        <SectionTitle style={{ margin: 0, border: 'none', padding: 0 }}>
                            Active Cases ({filteredCases.length})
                        </SectionTitle>
                    </div>

                    {filteredCases.length === 0 ? (
                        <Empty>No cases matching your criteria.</Empty>
                    ) : (
                        filteredCases.map(c => (
                            <div key={c.public_id} style={{ borderBottom: '1px solid var(--rule2)', padding: '12px 20px' }}>
                                <Row onClick={() => navigate(`/admin/cases/${c.public_id}`)}>
                                    <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)', width: 90, flexShrink: 0 }}>
                                        {c.public_id?.slice(0, 8)}...
                                    </span>
                                    <div style={{ flex: 1, minWidth: 0, paddingRight: 10 }}>
                                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {c.title}
                                        </div>
                                        {c.description && (
                                            <div style={{ fontSize: 11, color: 'var(--ink3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                                                {c.description}
                                            </div>
                                        )}
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                                        {c.priority && (
                                            <span style={{
                                                fontFamily: 'var(--mono)',
                                                fontSize: 8,
                                                padding: '1px 6px',
                                                background: c.priority === 'high' ? 'rgba(255,60,60,0.1)' : 'rgba(255,255,255,0.05)',
                                                color: c.priority === 'high' ? '#ff4444' : '#aaa',
                                                textTransform: 'uppercase'
                                            }}>
                                                {c.priority}
                                            </span>
                                        )}
                                        <Badge status={c.status} />
                                        <span style={{ color: 'var(--ink3)', fontSize: 12, marginLeft: 4 }}>▸</span>
                                    </div>
                                </Row>
                            </div>
                        ))
                    )}
                </div>

                {/* Direct Create Case Panel */}
                <div className="card" style={{ alignSelf: 'start' }}>
                    <SectionTitle>Open New Investigation Case</SectionTitle>
                    <ErrorBanner message={createError} />
                    <SuccessBanner message={createSuccess} />
                    <form onSubmit={handleCreate}>
                        <Field label="Case Title">
                            <input
                                className="input"
                                type="text"
                                value={form.title}
                                onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                                placeholder="e.g. Operation Cybershield"
                                required
                            />
                        </Field>

                        <Field label="Department">
                            <select
                                className="select"
                                value={form.dept_id}
                                onChange={e => setForm(f => ({ ...f, dept_id: e.target.value }))}
                                required
                            >
                                <option value="">Select Department...</option>
                                {departments.map(d => (
                                    <option key={d.public_id} value={d.public_id}>
                                        {d.name}
                                    </option>
                                ))}
                            </select>
                        </Field>

                        <Field label="Priority Level">
                            <select
                                className="select"
                                value={form.priority}
                                onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}
                            >
                                <option value="low">Low</option>
                                <option value="medium">Medium</option>
                                <option value="high">High</option>
                                <option value="critical">Critical</option>
                            </select>
                        </Field>

                        <Field label="Case Brief / Description">
                            <textarea
                                className="input"
                                value={form.description}
                                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                                placeholder="Details regarding case scope and objectives..."
                                style={{ height: 64, resize: 'none' }}
                            />
                        </Field>

                        <button
                            type="submit"
                            className="btn btn-primary"
                            style={{ width: '100%', marginTop: 6 }}
                            disabled={creating}
                        >
                            {creating ? 'Creating Case...' : 'Initialize Case'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}
