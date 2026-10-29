import React from 'react';

export function SectionTitle({ children }) {
    return (
        <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: '0.1em', color: 'var(--ink3)', textTransform: 'uppercase', marginBottom: 14, paddingBottom: 8, borderBottom: '1px solid var(--rule2)' }}>
            {children}
        </div>
    );
}

export function Row({ children, style, onClick }) {
    return (
        <div onClick={onClick} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '9px 0', borderBottom: '1px solid var(--rule2)', cursor: onClick ? 'pointer' : 'default', ...style }}>
            {children}
        </div>
    );
}

export function Empty({ children }) {
    return (
        <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)', padding: '24px 0', textAlign: 'center' }}>
            {children}
        </div>
    );
}

const STATUS_COLORS = {
    OPEN: { bg: 'rgba(255,255,255,0.06)', color: '#ccc' },
    IN_PROGRESS: { bg: 'rgba(255,170,0,0.1)', color: '#ffaa00' },
    CLOSED: { bg: 'rgba(255,255,255,0.04)', color: '#555' },
    ARCHIVED: { bg: 'rgba(255,255,255,0.04)', color: '#555' },
    PENDING: { bg: 'rgba(255,170,0,0.1)', color: '#ffaa00' },
    VERIFIED: { bg: 'rgba(0,200,120,0.1)', color: '#00c878' },
    VALID: { bg: 'rgba(0,200,120,0.1)', color: '#00c878' },
    UNCHANGED: { bg: 'rgba(0,200,120,0.1)', color: '#00c878' },
    RESTORED: { bg: 'rgba(0,180,255,0.15)', color: '#00d4ff' },
    FLAGGED: { bg: 'rgba(255,60,60,0.1)', color: '#ff4444' },
    TAMPERED: { bg: 'rgba(255,60,60,0.15)', color: '#ff2222' },
    TAMPER_DETECTED: { bg: 'rgba(255,60,60,0.2)', color: '#ff2222' },
    TAMPERED_AND_RESTORED: { bg: 'rgba(0,210,140,0.15)', color: '#00e699' },
    UPLOAD: { bg: 'rgba(0,180,255,0.1)', color: '#00b4ff' },
    VIEW: { bg: 'rgba(180,180,180,0.1)', color: '#b4b4b4' },
    VERIFY: { bg: 'rgba(160,100,255,0.1)', color: '#b084ff' },
    DOWNLOAD: { bg: 'rgba(255,170,0,0.1)', color: '#ffaa00' },
};

export function Badge({ status }) {
    const s = STATUS_COLORS[status?.toUpperCase()] || STATUS_COLORS.OPEN;
    return (
        <span style={{ display: 'inline-block', padding: '2px 8px', fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '0.06em', background: s.bg, color: s.color, textTransform: 'uppercase' }}>
            {status || 'OPEN'}
        </span>
    );
}

export function StatCard({ value, label }) {
    return (
        <div className="card">
            <div style={{ fontFamily: 'Stardom, serif', fontSize: 40, color: 'var(--ink)', lineHeight: 1, marginBottom: 8 }}>{value}</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--ink3)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>{label}</div>
        </div>
    );
}

export async function computeSHA256(file) {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function formatFileSize(bytes) {
    if (bytes === undefined || bytes === null || isNaN(bytes) || bytes === '') return '-';
    const num = Number(bytes);
    if (num === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(num) / Math.log(k));
    return `${parseFloat((num / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}
