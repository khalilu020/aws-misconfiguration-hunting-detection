# Cloud Security: AWS Misconfiguration Hunting & Detection

**Project 5** in a blue-team-focused cybersecurity portfolio. Extends prior SOC automation, detection engineering, DFIR, and network security monitoring work into the cloud domain — building, breaking, detecting, and fixing a small but realistic AWS environment, with cloud activity fed into the same Wazuh SIEM used across earlier projects.

## Repository Structure

```
.
├── README.md
├── configs/
│   ├── ossec_aws_wodle.xml            # Wazuh AWS S3 wodle config block
│   ├── wazuh-manager-override.conf    # systemd HOME env fix
│   └── local_internal_options.conf    # JSON decoder field-limit fix
├── policies/
│   ├── misconfig1_s3_public_bucket_policy.json
│   ├── wazuh_cloudtrail_reader_policy.json
│   └── designed_leaked_dev_user_policy.json   # designed, not executed — see Phase 5
├── detection-rules/
│   └── local_rules.xml                # custom Wazuh rule 100210
└── evidence/
    ├── screenshots/                   # phaseN_stepNumber_description.png
    └── scan-results/                  # Prowler CSV/HTML/JSON-OCSF exports
```

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Phase 1: AWS Setup & Planted Misconfigurations](#phase-1-aws-setup--planted-misconfigurations)
- [Phase 2: Scanning & Interpretation (Prowler)](#phase-2-scanning--interpretation-prowler)
- [Phase 3: CloudTrail](#phase-3-cloudtrail)
- [Phase 4: CloudTrail → Wazuh Integration](#phase-4-cloudtrail--wazuh-integration)
- [Phase 5: Attack Simulation (Scoped Down)](#phase-5-attack-simulation-scoped-down)
- [Phase 6: Custom Detection Rule](#phase-6-custom-detection-rule)
- [Phase 7: Remediation](#phase-7-remediation)
- [Cloud vs. Endpoint Detection: A Comparison](#cloud-vs-endpoint-detection-a-comparison)
- [Challenges & Lessons Learned](#challenges--lessons-learned)
- [Limitations](#limitations)
- [Skills Demonstrated](#skills-demonstrated)

---

## Overview

This project builds a deliberately vulnerable AWS environment, scans it with an open-source cloud security tool (Prowler), pipes AWS activity logs (CloudTrail) into an existing on-prem Wazuh SIEM, engineers a custom detection rule for high-risk IAM activity, and remediates the findings — closing the loop from **misconfiguration → detection → fix → verification** that a cloud security analyst performs in practice.

It deliberately builds on, rather than replaces, four prior projects:

| # | Project | Connection to this project |
|---|---|---|
| 1 | SOC automation (Wazuh/Shuffle/TheHive) | Same SIEM now ingests cloud data alongside endpoint/network data |
| 2 | MITRE ATT&CK detection engineering + MISP | Same rule-writing methodology applied to a new domain (cloud identity) |
| 3 | DFIR — memory forensics & timelines | Same "reconstruct what happened" mindset, applied to CloudTrail's API timeline instead of host memory |
| 4 | Network security monitoring (Suricata/Zeek) | Same "raw traffic in, meaningful alerts out" pipeline pattern, applied to cloud API traffic |

## Architecture

```
┌─────────────────────────┐
│   AWS Account (Free)     │
│                          │
│  ┌────────────────────┐  │
│  │ S3: public bucket   │  │
│  │ S3: SSE-S3 bucket   │  │
│  │ IAM: admin EC2 role │  │──── Prowler scan (read-only, SecurityAudit)
│  └────────────────────┘  │           │
│                          │           ▼
│  ┌────────────────────┐  │     Findings interpreted
│  │ CloudTrail (multi-  │  │     (critical/high/medium/low)
│  │ region trail)       │  │
│  └──────────┬──────────┘  │
│             │ writes to   │
│  ┌──────────▼──────────┐  │
│  │ S3: CloudTrail logs  │  │
│  └──────────┬──────────┘  │
└─────────────┼─────────────┘
              │ pulled via AWS S3 wodle
              │ (least-privilege IAM: s3:GetObject/ListBucket only)
              ▼
┌─────────────────────────┐
│  Debian VM: Wazuh Manager│
│  - aws-s3 wodle           │
│  - custom detection rule  │
│    (rule 100210, MITRE-   │
│     mapped)                │
│  - joins existing dash-   │
│    board (endpoint +      │
│    network + cloud)        │
└─────────────────────────┘
```

**Lab components:** Windows 10 (endpoint telemetry, prior projects), Kali (attacker/tooling), Debian (Wazuh manager, this project's ingestion target), AWS Free-tier account (new, this project).

---

## Phase 1: AWS Setup & Planted Misconfigurations

**Goal:** stand up a safe, cost-controlled AWS account, then deliberately introduce three realistic misconfigurations to discover and remediate later.

**Account setup:**
- AWS **Free plan** (not Paid) — chosen deliberately: on this plan the account is structurally incapable of being billed past its credit allotment; it auto-closes on expiry instead. Since AWS restructured free-tier onboarding in mid-2025 (moving from a blanket "12 months free" model to a $100–200 credit pool with a Free/Paid plan choice), this was a live decision, not a default.
- Guardrails: an **AWS Budget** ($5/month, alerts at 85%/100%) and a **CloudWatch billing alarm** (`EstimatedCharges` > $1). AWS's Cost Anomaly Detection was also auto-enabled as a third, unrequested layer.

**Planted misconfigurations:**

| # | Misconfiguration | Resource | Mechanism |
|---|---|---|---|
| 1 | Public S3 bucket | `khalil-portfolio-demo-bucket` | Bucket policy granting `s3:GetObject` to `Principal: "*"`, with per-bucket Block Public Access disabled |
| 2 | Over-permissive IAM role | `ec2-overpermissive-role` | `AdministratorAccess` managed policy attached to an EC2 trust relationship with no confused-deputy protection |
| 3 | Encryption gap | `khalil-unencrypted-demo-bucket` | Default SSE-S3 instead of SSE-KMS |

> **Note on Misconfig 3:** the original plan was a fully *unencrypted* bucket. AWS made baseline SSE-S3 encryption mandatory for all buckets in January 2023 — a fully unencrypted bucket is no longer possible to create. The finding was adjusted to the current, real-world equivalent: default AWS-managed encryption instead of customer-controlled KMS encryption, which is what modern scanners (including Prowler) actually flag. This mid-project pivot — recognizing a plan built on outdated assumptions and adjusting it — is itself a useful data point: cloud provider defaults change, and a security program has to track that.

---

## Phase 2: Scanning & Interpretation (Prowler)

**Tooling:** [Prowler](https://github.com/prowler-cloud/prowler), an open-source AWS security scanner mapping findings to CIS Benchmarks, MITRE ATT&CK, and 40+ other compliance frameworks. Run from a dedicated Kali VM under a scoped IAM user (`prowler-scanner`, `SecurityAudit` managed policy — read-only, no write/delete access anywhere in the account).

**Full account scan:** 630 checks executed, 235 failed (65.6%), 118 passed (32.96%).

### Findings confirmed against planted misconfigurations

| Planted issue | Prowler check | Severity | Result |
|---|---|---|---|
| Public bucket | `s3_bucket_public_access` | Critical | FAIL — "has public access due to bucket policy" |
| Over-permissive role | `iam_role_cross_service_confused_deputy_prevention` | High | FAIL — trust relationship has no `SourceArn`/`ExternalId` condition |
| Encryption gap | `s3_bucket_kms_encryption` | Medium | FAIL — SSE not configured with KMS |

### A finding beyond what was planted

`s3_account_level_public_access_blocks` (High) — **account-wide** Block Public Access was disabled, not just the individual bucket's setting. This is a more consequential gap than the single bucket: it means every *future* bucket created in the account inherits the same exposure risk by default, not just the one deliberately misconfigured. This distinction — a single resource fix vs. an account-wide guardrail fix — is a recurring theme in real cloud security remediation and was called out explicitly rather than treated as equivalent to the bucket-level finding.

### Interpretation notes (why "the tool said fail" isn't the end of the analysis)

- Roughly half of the 235 failures were **baseline AWS default gaps** present on any brand-new resource regardless of what was deliberately planted — missing bucket versioning, access logging, lifecycle policies, an account-wide password policy. These are real hygiene gaps worth noting once, not 15 separate incidents.
- Not every "FAIL" carries equal real-world risk. Example: `iam_user_hardware_mfa_enabled` failed for the `prowler-scanner` service account, but the paired check `iam_user_mfa_enabled_console_access` correctly passed — because that user has no console password to protect in the first place. Reading *why* a check passed or failed, not just its status, is the actual skill this phase was meant to build.

---

## Phase 3: CloudTrail

**What it is:** AWS's control-plane activity log — every console click, CLI command, and SDK call, tied to an identity, timestamp, and source IP. A multi-region trail was created, writing to a dedicated S3 bucket.

**Verification:** confirmed via CloudTrail Event History, which showed events retroactively — including `CreateUser`/`AttachUserPolicy`/`CreateAccessKey` calls made *before* the trail itself was created. This surfaced an important distinction: CloudTrail's 90-day Event History is active account-wide by default; a **trail** is what makes that data durable (S3-stored) and exportable, not what starts the logging itself.

---

## Phase 4: CloudTrail → Wazuh Integration

**Goal:** unify cloud activity with the existing endpoint/network telemetry from prior projects in one SIEM dashboard.

**Setup:** a second, separately scoped IAM user (`wazuh-cloudtrail-reader`) was created with an inline policy granting only `s3:GetObject` and `s3:ListBucket` on the CloudTrail log bucket specifically — deliberately kept separate from the `prowler-scanner` credential used in Phase 2, following least-privilege/separation-of-duties principles rather than reusing one broad credential across tools.

Wazuh's built-in `aws-s3` wodle (module) was configured to poll that bucket every 10 minutes and parse events using its native CloudTrail log-type parser.

**This integration did not work on the first attempt — see [Challenges & Lessons Learned](#challenges--lessons-learned) for the three distinct bugs diagnosed and fixed.**

**Verification:** confirmed via `archives.json` — live CloudTrail events (`AssumeRole`, `ListManagedNotificationEvents`, `AttachUserPolicy`, `CreateAccessKey`, etc.) flowing into Wazuh, each carrying full identity context (`userIdentity.arn`, `sourceIPAddress`, `eventName`, `eventSource`).

---

## Phase 5: Attack Simulation (Scoped Down)

**Original plan:** simulate a full IAM privilege-escalation chain — a low-privilege "leaked credential" IAM user using `iam:PassRole` + `ec2:RunInstances` to attach the over-permissive `ec2-overpermissive-role` to a new EC2 instance, then harvest that role's temporary credentials via the EC2 Instance Metadata Service (a well-documented real-world AWS privesc pattern, MITRE ATT&CK **T1078.004**).

**What actually happened:** this step was scoped out of the final build after weighing time cost against marginal learning value — the underlying concept (leaked credentials → role assumption → privilege escalation) is well-documented and was understood and planned in detail (see the exploit chain design above), but not executed live in this environment.

**Adjustment:** rather than skip detection entirely, Phase 6 was retargeted at real, already-present high-risk IAM events generated naturally during this project's own setup (`CreateAccessKey`, `AttachUserPolicy`) — both of which map to **T1098 (Account Manipulation)** and **T1136 (Create Account)**, the same persistence-stage techniques an attacker would trigger after any successful initial-access step, including the PassRole chain above. This kept Phase 6 empirically testable rather than purely theoretical.

---

## Phase 6: Custom Detection Rule

**Baseline check:** Wazuh's default AWS ruleset does include generic CloudTrail coverage — rule `80202` fires on **any** `iam.amazonaws.com` event at level 3 (low/informational), with an identical templated description regardless of what actually happened. A `CreateAccessKey` call and a routine read-only IAM `List*` call are logged identically. This is a realistic instance of a broader SOC problem: generic catch-all rules provide coverage but not triage, and over time they train analysts to deprioritize an entire alert category.

**Custom rule written** (`/var/ossec/etc/rules/local_rules.xml`):

```xml
<group name="aws,cloudtrail,iam,">
  <rule id="100210" level="10">
    <if_sid>80202</if_sid>
    <field name="aws.eventName">^CreateAccessKey$|^AttachUserPolicy$|^AttachRolePolicy$|^PutUserPolicy$|^CreateUser$</field>
    <description>AWS IAM: High-risk identity/permission change detected - $(aws.eventName) by $(aws.userIdentity.arn)</description>
    <mitre>
      <id>T1098</id>
      <id>T1136</id>
    </mitre>
  </rule>
</group>
```

- Escalates from level 3 to **level 10** specifically for identity/permission-modifying actions (new access keys, new users, new policy attachments), while leaving harmless read-only IAM calls at the low-severity default.
- Chains off the existing rule (`<if_sid>80202</if_sid>`) rather than re-parsing from scratch — an efficient pattern (broad rule catches the category, this narrows within it) rather than a competing/duplicate rule.
- Tagged with MITRE ATT&CK technique IDs, consistent with the methodology from Project 2.

**Validated with `wazuh-logtest`** against a real captured `CreateAccessKey` event (not synthetic test data):

```
id: '100210'
level: '10'
description: 'AWS IAM: High-risk identity/permission change detected - CreateAccessKey by arn:aws:iam::207283262526:root'
mitre.id: '['T1098', 'T1136']'
mitre.tactic: '['Persistence']'
mitre.technique: '['Account Manipulation', 'Create Account']'
**Alert to be generated.
```

Confirmed: rule fires correctly, dynamic field substitution works, and the alert would surface in the Wazuh dashboard.

---

## Phase 7: Remediation

All three planted misconfigurations, plus the account-level Block Public Access gap identified in Phase 2, were remediated:

- **Public bucket:** bucket policy removed from `khalil-portfolio-demo-bucket`.
- **Over-permissive IAM role:** `AdministratorAccess` detached from `ec2-overpermissive-role`.
- **Encryption gap:** both S3 buckets switched from SSE-S3 to SSE-KMS (AWS-managed `aws/s3` key).
- **Account-level Block Public Access:** enabled account-wide (all four sub-settings) — closing the broader structural gap, not just the individual bucket.

> **Re-scan:** a fix pass was applied to the live environment following the same steps Prowler originally flagged. A full before/after `prowler aws --service s3 iam` re-scan comparison table (with the specific check counts) was not captured as terminal output within this documentation session — recommended as the immediate next action to complete this section with exact numbers before publishing.

---

## Cloud vs. Endpoint Detection: A Comparison

A direct, hands-on comparison — not theoretical — based on working with both data types across this project and Projects 1–4.

| Dimension | Endpoint (Sysmon / Windows Event Logs, Projects 1–4) | Cloud (CloudTrail, this project) |
|---|---|---|
| **What's being watched** | A single host: processes, files, registry, network connections on that machine | An entire AWS account: API calls against AWS's control plane |
| **Core identity concept** | OS user account (`User` field), tied to a login session on that host | IAM principal (`userIdentity.arn`) — a user, role, or assumed-role session, often ephemeral and tied to temporary credentials |
| **Example "suspicious" event** | Event ID 1 (`ProcessCreate`): unusual `Image`/`CommandLine`/`ParentImage` combination | `CreateAccessKey` or `AttachUserPolicy`: an identity granting itself or another identity more power |
| **Volume driver** | Every process spawn, file write, registry change on one machine | Every console click, CLI call, SDK call, and *automated service-to-service call* (e.g. `AssumeRole` invoked by AWS's own internal services) across an entire account and all regions |
| **Detection logic pattern** | Behavioral/sequence-based: parent-child process chains, LOLBins, unusual file paths | Identity/action-based: who did what, from where, using what kind of credential (root vs. IAM user vs. assumed role) |
| **What "lateral movement" looks like** | A process on Host A spawning a remote connection to Host B | An identity assuming a role or attaching a policy to gain a new set of permissions — no "movement" across physical hosts required |
| **Noise/tuning challenge** | Legitimate admin tooling can resemble attacker tradecraft (e.g. PowerShell) | AWS's own internal services trigger huge volumes of legitimate cross-service API calls (this project's logs show dozens of `AssumeRole` events driven entirely by AWS's own `resource-explorer-2` service, no human involved) |

**Practical takeaway from building this pipeline directly:** the underlying detection question — *"who did this, and should they have been able to?"* — doesn't change between the two domains. What changes is the vocabulary and the baseline of "normal." A defender moving from endpoint to cloud detection isn't learning a new discipline so much as re-learning what "identity" and "action" mean in a control-plane context instead of an OS context.

---

## Challenges & Lessons Learned

This section documents real debugging performed during the project, not a cleaned-up happy path — three distinct, sequential infrastructure issues were diagnosed and resolved while wiring CloudTrail into Wazuh (Phase 4):

1. **`wazuh-analysisd: ERROR: Too many fields for JSON decoder`** — Wazuh's default JSON decoder caps at 256 fields per event; CloudTrail events (especially IAM/S3 policy-heavy ones) can exceed this. Root cause confirmed via Wazuh's own GitHub issue tracker as a known, documented limitation of the AWS module. Fixed by raising `analysisd.decoder_order_size` to 1024 in `local_internal_options.conf`. Documented limitation: even the maximum setting does not guarantee elimination for unusually large events — a genuine constraint of the classic JSON decoder, not a configuration mistake.
2. **`The config profile (wazuh-cloudtrail) could not be found`** — despite a correctly formatted `~/.aws/credentials` file at the `wazuh` service account's home directory (`/var/ossec`), boto3 couldn't locate it. Root cause: the `wazuh-manager` systemd service does not inherit `$HOME` the way an interactive shell session does, even when both run as the same Linux user — a common but easy-to-miss gap between systemd-launched services and manually tested shell sessions. Fixed via a systemd override (`/etc/systemd/system/wazuh-manager.service.d/override.conf`) explicitly setting `Environment="HOME=/var/ossec"`.
3. **`No logs found in 'AWSLogs/AWSLogs/'`** — a redundant `<path>AWSLogs</path>` tag in the wodle config caused Wazuh's CloudTrail-type bucket parser (which already auto-prepends that prefix internally) to double it. Fixed by removing the explicit path tag entirely.

**Broader lesson:** each of these was a case where the *component in isolation* looked correct (credentials file present and correctly permissioned; config block syntactically valid XML; JSON payload well-formed) but the *interaction between components* was the actual fault — a pattern common in real infrastructure debugging, and a reminder that "verify each piece independently" and "verify the pieces together" are two different, both-necessary steps.

---

## Limitations

- The planned live IAM privilege-escalation simulation (Phase 5) was scoped out of the final build; the exploit chain was designed and documented conceptually but not executed against the live environment. Detection (Phase 6) was validated against real, naturally occurring high-risk IAM events instead of a purpose-built attack, which is empirically weaker evidence of detecting *novel* attacker behavior specifically, though the underlying technique coverage (T1098/T1136) is the same either way.
- The Phase 7 before/after Prowler re-scan was not captured with exact output in this documentation pass; remediation actions were applied but the quantitative "before N fails / after N fails" comparison should be completed before treating this as a finished portfolio piece.
- This is a single-account, single-region-focus lab environment (though CloudTrail itself is multi-region) — it does not reflect the scale, multi-account structure (AWS Organizations), or SSO/federation patterns of a real enterprise AWS environment.
- The custom Wazuh detection rule (100210) was validated via `wazuh-logtest` replay of a captured event, not via a live, real-time triggering end-to-end test through the full ingestion pipeline.

---

## Skills Demonstrated

- AWS account governance: cost guardrails, Free/Paid plan trade-off analysis, IAM least-privilege design across three separately scoped service accounts
- Cloud security scanning and **interpretation** (not just tool execution) using Prowler, cross-referenced against CIS/MITRE ATT&CK mappings
- Cloud-native logging architecture: CloudTrail trail design, management vs. data event scoping
- SIEM integration engineering: Wazuh AWS module configuration, systemd service environment debugging, JSON decoder tuning
- Detection engineering: custom Wazuh rule authored, chained off existing coverage, MITRE ATT&CK-mapped, and empirically validated against real log data
- Applied comparative analysis between cloud (identity/API-based) and endpoint (process/file-based) detection models, grounded in hands-on work across both domains
