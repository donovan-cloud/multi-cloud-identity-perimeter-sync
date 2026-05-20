# Automated Hybrid-Cloud Identity Governance Engine (Entra ID -> AWS IAM)

An enterprise-grade, cross-cloud identity reconciliation system designed to eliminate the latency between corporate de-provisioning events and cloud infrastructure access boundaries. This engine syncs Microsoft Entra ID (Azure AD) corporate identity status anomalies with AWS IAM control planes to enforce instantaneous cross-cloud session termination.

## System Architecture & Telemetry Flow

1. **Identity Anomaly:** A corporate identity event occurs in Microsoft Entra ID (e.g., account deactivation, high risk threshold reached).
2. **Event Ingestion:** An Azure Function interceptor processes the Microsoft Graph webhook payload.
3. **Cross-Cloud Routing:** The event is signed and pushed securely via HTTPS payload to an Amazon API Gateway endpoint.
4. **Enforcement & Blast Radius Mitigation:** An AWS Lambda handler processes the cross-cloud identity token, parses the target user mappings, and dynamically injects restrictive policy boundaries and session invalidations across the AWS ecosystem.

---

> **[2026-05-20 15:10:02] [INFO]** Multi-Cloud Identity Sync Core active. Awaiting Graph webhook telemetry...  
> **[2026-05-20 15:14:22] [ALERT]** AZURE_ENTRA_ID: Lifecycle Event Captured for identity: [dev-lead@fintech.com]  
> **[2026-05-20 15:14:22] [WARN]** IDENTITY_STATUS: Account Status Changed to [accountEnabled: False] (Administrative Deactivation)  
> **[2026-05-20 15:14:23] [ROUTING]** Forwarding identity payload via secure HTTPS tunnel to AWS API Gateway...  
> **[2026-05-20 15:14:23] [INFO]** AWS_API_GATEWAY: Payload received and cryptographically verified. Routing to Lambda.  
> **[2026-05-20 15:14:24] [ACTION]** Resolving Entra ID UPN [dev-lead@fintech.com] to cross-cloud AWS mapping pattern...  
> **[2026-05-20 15:14:24] [CRITICAL]** MATCH FOUND: Target IAM Role mapped to user: [FinTech-Engineering-Lead-Role]  
> **[2026-05-20 15:14:25] [EXECUTION]** Pushing global Revocation Statement to target IAM Role...  
> **[2026-05-20 15:14:26] [SUCCESS]** Active STS temporary credentials invalidated. Revocation timestamp set to current runtime.  
> **[2026-05-20 15:14:26] [INFO]** Hybrid-Cloud identity perimeter successfully synchronized. Cross-cloud isolation time: 4.1 seconds.

---

## Security Playbook Implementations Included

* **Playbook 01 (Cross-Cloud Token Translation):** Translates Azure Microsoft Graph UPN identities directly into AWS Federated IAM Role structures based on strict corporate schema definitions.
* **Playbook 02 (Immediate STS Session Revocation):** Dynamically applies an inline explicit `Deny` block matching a timestamp criteria (`TokenIssueTime < CurrentTime`) to break all active CLI/Console developer sessions instantaneously.
