// Relative URLs — proxied via vite.config.js
const AUTH_BASE = "/api/v1/auth";
const CASE_BASE = "/api/v1/cases";
const EVIDENCE_BASE = "/api/v1/evidence";
const AUDIT_BASE = "/api/v1/audit";

async function request(url, options = {}) {
  const token = localStorage.getItem("sdes_token");
  const res = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
    ...options,
  });

  const text = await res.text();

  let data = {};
  try {
    data = JSON.parse(text);
  } catch {}

  if (!res.ok) {
    throw new Error(text || "Request failed");
  }

  return data;
}

export async function loginUser({ email, password }) {
  return request(`${AUTH_BASE}/login`, {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function loginAdmin({ email, password }) {
  return request(`${AUTH_BASE}/admin/login`, {
    method: "POST",
    body: JSON.stringify({ admin_email: email, admin_password: password }),
  });
}

export async function registerAdmin({ name, email, password, orgName }) {
  return request(`${AUTH_BASE}/admin/register`, {
    method: "POST",
    body: JSON.stringify({
      admin_name: name,
      admin_email: email,
      admin_password: password,
      org_name: orgName,
    }),
  });
}

export async function createMember({
  name,
  email,
  password,
  org_role,
  department_id,
  department_role,
}) {
  return request(`${AUTH_BASE}/admin/create-user`, {
    method: "POST",
    body: JSON.stringify({
      name,
      email,
      password,
      org_role,
      department_id,
      department_role,
    }),
  });
}

export async function getCases(departmentId, userId) {
  let url = `${CASE_BASE}`;
  const params = [];
  if (departmentId) params.push(`department_id=${departmentId}`);
  if (userId) params.push(`user_id=${userId}`);
  if (params.length > 0) {
    url += `?${params.join("&")}`;
  }
  return request(url);
}

export async function getOrgUsers() {
  return request(`${AUTH_BASE}/admin/get-org-users`);
}

export async function createDepartment({ name }) {
  return request(`${AUTH_BASE}/admin/create-department`, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export async function createRole({
  name,
  description,
  permissions,
  scopeType,
  scopeId,
}) {
  return request(`${AUTH_BASE}/create-role`, {
    method: "POST",
    body: JSON.stringify({
      name,
      description,
      permissions,
      scope: { type: scopeType, public_id: scopeId },
    }),
  });
}

export async function deleteRole(roleName, scopeType, scopeId) {
  return request(`${AUTH_BASE}/delete-role`, {
    method: "POST",
    body: JSON.stringify({
      name: roleName,
      scope: { type: scopeType, public_id: scopeId },
    }),
  });
}

export async function getAllPermissions() {
  return request(`${AUTH_BASE}/get-all-permissions`);
}

export async function getRolePermissions(roleName, scopeType, scopeId) {
  const url =
    scopeType && scopeId
      ? `${AUTH_BASE}/get-role-permissions/${roleName}?scope_type=${scopeType}&scope_id=${scopeId}`
      : `${AUTH_BASE}/get-role-permissions/${roleName}`;
  return request(url);
}

export async function attachPermissionsToRole({
  roleName,
  scopeType,
  scopeId,
  permissions,
}) {
  return request(`${AUTH_BASE}/attach-permissions-to-role`, {
    method: "POST",
    body: JSON.stringify({
      role_name: roleName,
      scope: { type: scopeType, public_id: scopeId },
      permission_names: permissions,
    }),
  });
}

export async function detachPermissionsFromRole({
  roleName,
  scopeType,
  scopeId,
  permissions,
}) {
  return request(`${AUTH_BASE}/detach-permissions-from-role`, {
    method: "POST",
    body: JSON.stringify({
      role_name: roleName,
      scope: { type: scopeType, public_id: scopeId },
      permission_names: permissions,
    }),
  });
}

export async function getOrgRoles(scopeType) {
  const url = scopeType
    ? `${AUTH_BASE}/get-org-roles?scope_type=${scopeType}`
    : `${AUTH_BASE}/get-org-roles`;
  return request(url);
}

export async function getUserRoles(userId) {
  return request(`${AUTH_BASE}/get-user-roles/${userId}`);
}

export async function getOrgDepartments() {
  return request(`${AUTH_BASE}/admin/get-org-departments`);
}

export async function updateUserDepartment({ userId, departmentId }) {
  return request(`${AUTH_BASE}/admin/update-user-department`, {
    method: "POST",
    body: JSON.stringify({ user_id: userId, department_id: departmentId }),
  });
}

export async function deleteDepartment(departmentId) {
  return request(`${AUTH_BASE}/admin/delete-department`, {
    method: "DELETE",
    body: JSON.stringify({ department_id: departmentId }),
  });
}

export async function createCase({ title, description, priority, dept_id }) {
  return request(`${CASE_BASE}`, {
    method: "POST",
    body: JSON.stringify({ title, description, priority, dept_id }),
  });
}

export async function getCaseById(id) {
  return request(`${CASE_BASE}/${id}`);
}

export async function assignUserToCase({ caseId, userId }) {
  return request(`${CASE_BASE}/${caseId}/users`, {
    method: "POST",
    body: JSON.stringify({ user_id: userId }),
  });
}

export async function getCaseUsers(caseId) {
  return request(`${CASE_BASE}/${caseId}/users`);
}

export async function updateCaseStatus({ caseId, status }) {
  return request(`${CASE_BASE}/${caseId}/status`, {
    method: "PUT",
    body: JSON.stringify({ status }),
  });
}

export async function deleteCase(caseId) {
  return request(`${CASE_BASE}/${caseId}`, {
    method: "DELETE",
  });
}

export async function getEvidence(caseId) {
  const url = caseId ? `${EVIDENCE_BASE}?case_id=${caseId}` : `${EVIDENCE_BASE}`;
  return request(url);
}

export async function uploadEvidence(formData) {
  const token = localStorage.getItem("sdes_token");
  const res = await fetch(`${EVIDENCE_BASE}`, {
    method: "POST",
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: formData,
  });
  const text = await res.text();
  let data = {};
  try {
    data = JSON.parse(text);
  } catch {}
  if (!res.ok) {
    throw new Error(data.error || text || "Upload failed");
  }
  return data;
}

export async function downloadEvidence(evidenceId) {
  const token = localStorage.getItem("sdes_token");
  const res = await fetch(`${EVIDENCE_BASE}/${evidenceId}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error("Download failed");
  }
  return res.blob();
}

export async function exportCaseEvidenceZip(casePublicId) {
  const token = localStorage.getItem("sdes_token");
  const res = await fetch(`${EVIDENCE_BASE}/case/${casePublicId}/export`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = "Export failed";
    try {
      const data = JSON.parse(text);
      msg = data.error || msg;
    } catch {}
    throw new Error(msg);
  }
  return res.blob();
}

export async function verifyEvidence(evidenceId) {
  return request(`${AUDIT_BASE}/evidence/${evidenceId}/verify`);
}

export async function revertEvidence(evidenceId) {
  return request(`${EVIDENCE_BASE}/${evidenceId}/revert`, { method: "POST" });
}

export async function getCustodyLogs(params = {}) {
  const cleanParams = Object.fromEntries(
    Object.entries(params).filter(
      ([_, v]) => v !== undefined && v !== null && v !== "",
    ),
  );
  const query = new URLSearchParams(cleanParams).toString();
  return request(`${AUDIT_BASE}/custody-logs${query ? `?${query}` : ""}`);
}

export async function getCustodyLogById(id) {
  return request(`${AUDIT_BASE}/custody-logs/${id}`);
}

export async function getAuditLogs(params = {}) {
  const cleanParams = Object.fromEntries(
    Object.entries(params).filter(
      ([_, v]) => v !== undefined && v !== null && v !== "",
    ),
  );
  const query = new URLSearchParams(cleanParams).toString();
  return request(`${AUDIT_BASE}/audit-logs${query ? `?${query}` : ""}`);
}

export async function getAuditLogById(id) {
  return request(`${AUDIT_BASE}/audit-logs/${id}`);
}

export async function verifyAuditLogs({ scope, id, autoRestore = true }) {
  return request(`${AUDIT_BASE}/logs/verify`, {
    method: "POST",
    body: JSON.stringify({ scope, id, auto_restore: autoRestore }),
  });
}

export async function getIntegrityAlerts(params = {}) {
  const cleanParams = Object.fromEntries(
    Object.entries(params).filter(
      ([_, v]) => v !== undefined && v !== null && v !== "",
    ),
  );
  const query = new URLSearchParams(cleanParams).toString();
  return request(`${AUDIT_BASE}/alerts${query ? `?${query}` : ""}`);
}

export async function getUserDetails(userId) {
  return request(`${AUTH_BASE}/admin/get-user/${userId}`);
}

export async function deleteUser(userId) {
  return request(`${AUTH_BASE}/admin/delete-user/${userId}`, {
    method: "DELETE",
  });
}

export async function assignUserRoles({
  userId,
  roleNames,
  scopeType,
  scopeId,
}) {
  return request(`${AUTH_BASE}/assign-role`, {
    method: "POST",
    body: JSON.stringify({
      target_user_id: userId,
      role_names: roleNames,
      scope: { type: scopeType, public_id: scopeId },
    }),
  });
}

export async function revokeUserRoles({
  userId,
  roleNames,
  scopeType,
  scopeId,
}) {
  return request(`${AUTH_BASE}/revoke-role`, {
    method: "POST",
    body: JSON.stringify({
      target_user_id: userId,
      role_names: roleNames,
      scope: { type: scopeType, public_id: scopeId },
    }),
  });
}

export async function removeUserFromCase({ caseId, userId }) {
  return request(`${CASE_BASE}/${caseId}/users/${userId}`, {
    method: "DELETE",
  });
}
