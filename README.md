# FDS Penetration Test Report

**Target:** FDS Development Application (Bank Sulut Go)  
**Period:** November 9–10, 2026  
**Classification:** Authorized Lab Testing  
**Status:** Final

---

## Repository Structure

```
.
├── README.md                          # This file
├── reports/
│   ├── PENTEST_REPORT.md             # Main penetration test report
│   ├── POC_REPORT.md                  # PoC evidence and reassessment
│   └── POC_BURP_FORMAT.md            # Burp Suite Repeater format requests
├── tools/
│   └── login.py                       # Automated login script
└── evidence/
    └── poc_evidence.json              # Raw response evidence (redacted)
```

---

## Summary

Comprehensive penetration testing was performed on the FDS (Fraud Detection System) development application against two authorized test accounts (Checker and Approver roles). The application implements strong baseline controls including JWT signature validation, brute-force lockout, single-device sessions, and HTTPS with HSTS.

### Key Findings

| Severity | Count | Status |
|---|---|---|
| High | 0 | None confirmed |
| Medium | 3 | 2 open + 1 pending business confirmation |
| Low | 4 | Open |
| Informational | 5 | Documented |
| Closed | 3 | Expected design or false positive |

### Open Findings

- **FDS-001** (Medium): CSP permits `unsafe-inline` and `unsafe-eval`
- **FDS-009** (Medium): Note body size limit implicit
- **FDS-013** (Medium, pending): Checker accesses system configuration; Approver blocked — **requires business policy confirmation**
- **FDS-002, FDS-003, FDS-007, FDS-010** (Low/Info): Various hardening recommendations

### Closed Findings

- **FDS-011, FDS-012**: Cross-case note read/write — confirmed as expected design (all users can access all cases per developer clarification)
- **FDS-014**: Action without role check — identified as `refreshSessionAction` (session idle timer), not a workflow bypass

---

## Testing Scope

**Authorized Accounts:**
- `endangchecker@gmail.com` (Checker role)
- `endangapprover@gmail.com` (Approver role)

**Technology Stack:**
- Next.js App Router
- Server Actions (deployment IDs: `6be8fb3`, `54ac33f`)
- JWT (HS256) session management
- nginx reverse proxy

**Testing Activities:**
- Authentication bypass attempts (JWT tampering, `alg:none`, role injection)
- Authorization testing (RBAC, IDOR, BAC)
- CSRF testing (Origin validation, SameSite)
- Next.js specific vulnerabilities (CVE-2025-29927, `/_next/image` SSRF)
- Business logic review from JavaScript bundles
- Cache poisoning attempts
- Input validation (XSS, note size limits)

---

## Critical Note on FDS-013

The only finding requiring immediate stakeholder decision is **FDS-013**:

**Observation:** Checker role receives system fraud detection configuration (`riskScore`, `autoResolve`, `overdue`) while Approver role receives `403 Forbidden` for the same action.

**Technical verification:** Checker JWT explicitly contains permission `view_case_configuration`; the asymmetry is consistent with permission enforcement, not an authorization bypass.

**Business question:** Is permission `view_case_configuration` intentionally granted to operational Checker role, or is this a misconfiguration?

**Recommended action:** Developer/stakeholder to confirm permission policy. If intentional, close as expected behavior. If not, revoke the permission from Checker role definition.

---

## Positive Security Controls Verified

✅ JWT HS256 signature validation enforced  
✅ `alg:none` bypass rejected  
✅ Role and permission tampering rejected  
✅ Expired tokens rejected  
✅ Account lockout after 2 failed attempts  
✅ Single-device session enforcement  
✅ Secure, HttpOnly, SameSite=Lax cookies  
✅ HSTS with includeSubDomains  
✅ CSRF protection via Next.js Origin validation  
✅ CVE-2025-29927 not applicable (middleware enforced)  
✅ `/_next/image` SSRF allowlist active  

---

## Important Disclaimers

1. **No confirmed High severity vulnerabilities.** Initial classifications were revised after developer clarification and additional technical analysis.

2. **Session tokens and credentials are redacted** from all files in this repository. Do not include raw session files (`cs2.txt`, `as2.txt`, cookie jars) in distribution.

3. **Test markers remain in database:** Note ID `01a1c255-1d5b-7a00-a327-f67c3609c6c9` with body `[PENTEST-MARKER-CROSS-CASE]` was created during testing and should be cleaned up per lab procedures.

4. **Deployment-specific action IDs:** Next.js Server Action IDs change with each deployment. PoC requests reference specific deployment IDs and may not work on newer deployments without updating action IDs.

5. **Development environment only:** All testing was performed on `fds-dev-sites.skyworx.co.id`. Production environment was not in scope and was not tested.

---

## Recommendations

### Immediate
1. Confirm FDS-013 permission policy
2. Implement nonce-based CSP (replace `unsafe-inline`/`unsafe-eval`)
3. Add explicit note body length validation

### Short-Term
4. Return proper HTTP status codes for authorization failures (not 500)
5. Audit all note output sinks for HTML encoding
6. Implement IP-based rate limiting alongside account lockout

### Long-Term
7. Before enabling multi-tenancy, enforce organization-level isolation in all case/note queries
8. Test server-side workflow transition enforcement (self-approval, state skipping, double approval)

---

## Contact & Authorization

This penetration test was conducted under authorized lab testing engagement. All accounts used were provided specifically for security testing purposes.

**Tester:** VANTA  
**Client:** [Redacted]  
**Authorization:** Lab testing agreement  
**Date:** November 9–10, 2026

---

## File Descriptions

### reports/PENTEST_REPORT.md
Complete penetration test report with 11 sections covering authentication, authorization, Next.js surface, input validation, and business logic. Includes detailed remediation recommendations and positive security control verification.

### reports/POC_REPORT.md
Proof of concept reassessment document explaining the status of each observation, why certain findings were closed, and what evidence supports or refutes each claim. Written to prevent misinterpretation of technical observations as confirmed vulnerabilities.

### reports/POC_BURP_FORMAT.md
HTTP request/response pairs in Burp Suite Repeater format for reproducing each technical observation. Includes CSRF Origin validation tests, Next.js CVE checks, and authorization boundary verification.

### tools/login.py
Python script automating the Next.js Server Action login flow with AES-256-GCM password envelope generation. Handles single-device session enforcement and cookie extraction.

### evidence/poc_evidence.json
Timestamped raw response data from live testing. **Sensitive fields redacted.** Includes response bodies, HTTP status codes, and verification metadata for each observation.

---

## License

This report is confidential and intended solely for the client organization. Unauthorized distribution or reproduction is prohibited.
