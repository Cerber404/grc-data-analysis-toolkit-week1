#!/usr/bin/env python3
"""
GRC Data Analysis Toolkit - Week 1
Course: Cybersecurity Policy & Risk Management

Case company: MedCore Regional Hospital

This script contains:
1. Organizational Profile Analyzer
2. CIA Triad Impact Classifier
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List
import re


def identify_applicable_regulations(org_profile: dict) -> list:
    """
    Identify applicable regulatory frameworks based on organization characteristics.

    Returns:
        list: A list of dictionaries containing regulation name, reason,
              priority, and a key requirement.
    """
    regulations = []
    sector = org_profile.get("sector", "").lower()
    employees = org_profile.get("employees", 0)

    if org_profile.get("handles_health_data", False) or sector in [
        "healthcare", "hospital", "clinic"
    ]:
        regulations.append({
            "name": "HIPAA Security Rule",
            "reason": "Organization handles Protected Health Information (PHI)",
            "priority": "MANDATORY",
            "key_requirement": "Risk analysis and administrative, physical, and technical safeguards",
        })

    if org_profile.get("processes_payments", False):
        regulations.append({
            "name": "PCI-DSS v4.0",
            "reason": "Organization processes, stores, or transmits cardholder data",
            "priority": "MANDATORY",
            "key_requirement": "PCI-DSS control requirements and regular assessment",
        })

    if org_profile.get("handles_eu_personal_data", False):
        regulations.append({
            "name": "GDPR",
            "reason": "Organization processes personal data of EU residents",
            "priority": "MANDATORY",
            "key_requirement": "Lawful basis, data subject rights, and breach notification",
        })

    if sector in ["banking", "financial services", "insurance", "fintech"]:
        regulations.append({
            "name": "GLBA Safeguards Rule",
            "reason": "Financial institution subject to Gramm-Leach-Bliley Act",
            "priority": "MANDATORY",
            "key_requirement": "Written information security program and qualified oversight",
        })

    if org_profile.get("public_company", False):
        regulations.append({
            "name": "SOX IT Controls (Section 404)",
            "reason": "Publicly traded company subject to Sarbanes-Oxley",
            "priority": "MANDATORY",
            "key_requirement": "Annual internal control assessment and auditor attestation",
        })

    if org_profile.get("is_federal_contractor", False) or sector == "government":
        regulations.append({
            "name": "FISMA / NIST SP 800-53",
            "reason": "Federal agency or contractor subject to FISMA",
            "priority": "MANDATORY",
            "key_requirement": "Authorization to Operate (ATO) and continuous monitoring",
        })

    if org_profile.get("handles_cui", False) or sector == "defense":
        regulations.append({
            "name": "CMMC 2.0",
            "reason": "Defense contractor handles Controlled Unclassified Information",
            "priority": "MANDATORY",
            "key_requirement": "CMMC assessment requirements for DoD contracts",
        })

    if org_profile.get("california_presence", False) and employees >= 1:
        regulations.append({
            "name": "CCPA/CPRA",
            "reason": "Organization does business in California and may meet revenue/data thresholds",
            "priority": "LIKELY APPLICABLE - verify thresholds",
            "key_requirement": "Consumer access, deletion, opt-out rights, and data mapping",
        })

    regulations.append({
        "name": "NIST Cybersecurity Framework 2.0",
        "reason": "Voluntary but widely used cybersecurity governance baseline",
        "priority": "STRONGLY RECOMMENDED",
        "key_requirement": "Govern, Identify, Protect, Detect, Respond, and Recover",
    })

    return regulations


def assess_governance_maturity(org_profile: dict) -> dict:
    """
    Score GRC maturity from 1 to 5.

    1 = Initial / Ad-hoc
    2 = Developing
    3 = Defined
    4 = Managed
    5 = Optimizing
    """
    scores = {"governance": 1, "risk": 1, "compliance": 1}
    evidence = {"governance": [], "risk": [], "compliance": []}

    if org_profile.get("has_ciso", False):
        scores["governance"] += 1
        evidence["governance"].append("+ CISO or dedicated security leader exists")
    if org_profile.get("has_security_committee", False):
        scores["governance"] += 1
        evidence["governance"].append("+ Security/risk committee established")
    if org_profile.get("board_security_reporting", False):
        scores["governance"] += 1
        evidence["governance"].append("+ Board receives regular security reporting")
    if org_profile.get("security_budget_defined", False):
        scores["governance"] += 0.5
        evidence["governance"].append("+ Defined security budget allocation")
    if org_profile.get("policy_suite_current", False):
        scores["governance"] += 0.5
        evidence["governance"].append("+ Policy suite reviewed within 12 months")

    if org_profile.get("has_risk_register", False):
        scores["risk"] += 1
        evidence["risk"].append("+ Formal risk register maintained")
    if org_profile.get("annual_risk_assessment", False):
        scores["risk"] += 1
        evidence["risk"].append("+ Annual formal risk assessment conducted")
    if org_profile.get("continuous_risk_monitoring", False):
        scores["risk"] += 1
        evidence["risk"].append("+ Continuous risk monitoring in place")
    if org_profile.get("risk_appetite_documented", False):
        scores["risk"] += 1
        evidence["risk"].append("+ Risk appetite formally documented and approved")

    if org_profile.get("compliance_program", False):
        scores["compliance"] += 1
        evidence["compliance"].append("+ Formal compliance program exists")
    if org_profile.get("last_audit_passed", False):
        scores["compliance"] += 1
        evidence["compliance"].append("+ Most recent audit passed")
    if org_profile.get("security_training", False):
        scores["compliance"] += 1
        evidence["compliance"].append("+ Security awareness training program active")
    if org_profile.get("vendor_risk_program", False):
        scores["compliance"] += 1
        evidence["compliance"].append("+ Third-party/vendor risk assessment program")

    for category in scores:
        scores[category] = min(5, round(scores[category], 1))

    return {
        "scores": scores,
        "evidence": evidence,
        "overall_maturity": round(sum(scores.values()) / 3, 1),
    }


def maturity_label(score: float) -> str:
    """Convert a maturity score into a readable label."""
    if score < 2:
        return "Initial/Ad-hoc"
    if score < 3:
        return "Developing"
    if score < 4:
        return "Defined"
    if score < 5:
        return "Managed"
    return "Optimizing"


def generate_grc_summary_report(org_profile: dict) -> str:
    """Generate a formatted GRC readiness report."""
    regulations = identify_applicable_regulations(org_profile)
    maturity = assess_governance_maturity(org_profile)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines = [
        "=" * 70,
        "GRC READINESS ASSESSMENT REPORT",
        f"Organization: {org_profile.get('org_name', 'Unknown')}",
        f"Generated: {now}",
        "=" * 70,
        "",
        "APPLICABLE REGULATORY FRAMEWORKS",
        "-" * 70,
    ]

    mandatory = [r for r in regulations if r["priority"] == "MANDATORY"]
    recommended = [r for r in regulations if r["priority"] != "MANDATORY"]

    lines.append(f"MANDATORY ({len(mandatory)} frameworks):")
    for regulation in mandatory:
        lines.append(f"[REQUIRED] {regulation['name']}")
        lines.append(f"Reason: {regulation['reason']}")
        lines.append(f"Key Req: {regulation['key_requirement']}")
        lines.append("")

    if recommended:
        lines.append(f"RECOMMENDED ({len(recommended)} frameworks):")
        for regulation in recommended:
            lines.append(f"[RECOMMEND] {regulation['name']}")
            lines.append(f"Reason: {regulation['reason']}")
            lines.append("")

    lines.extend([
        "GRC MATURITY SCORES (1 = Initial, 5 = Optimizing)",
        "-" * 70,
    ])

    for dimension, score in maturity["scores"].items():
        lines.append(f"{dimension.upper():<12} {score}/5.0 ({maturity_label(score)})")
        for item in maturity["evidence"][dimension]:
            lines.append(f"  {item}")

    overall = maturity["overall_maturity"]
    if overall < 2:
        overall_status = "CRITICAL GAPS - IMMEDIATE ACTION NEEDED"
    elif overall < 3:
        overall_status = "DEVELOPING - SIGNIFICANT IMPROVEMENT NEEDED"
    elif overall < 4:
        overall_status = "DEFINED - CONTINUE BUILDING CONSISTENCY"
    else:
        overall_status = "MANAGED - FOCUS ON OPTIMIZATION"

    lines.extend([
        "",
        f"OVERALL GRC MATURITY: {overall}/5.0",
        overall_status,
        "",
        "=" * 70,
    ])

    return "\n".join(lines)


@dataclass
class SecurityEvent:
    """Represent one security incident used for CIA classification."""
    name: str
    description: str


def classify_cia_impact(event: SecurityEvent) -> dict:
    """
    Classify an event by Confidentiality, Integrity, and Availability impact.
    """
    text = f"{event.name} {event.description}".lower()

    confidentiality_keywords = [
        "data exposed", "leaked", "unauthorized access", "breach",
        "exfiltrat", "credential", "eavesdrop", "intercept",
        "disclosed", "stolen", "read", "viewed by unauthorized",
    ]
    integrity_keywords = [
        "modified", "tampered", "altered", "corrupted", "falsif",
        "changed without", "forged", "injected", "replaced",
        "sql inject", "man-in-the-middle",
    ]
    availability_keywords = [
        "unavailable", "down", "outage", "ransomware",
        "ddos", "denial of service", "locked out", "deleted",
        "wiped", "destroyed", "inaccessible",
    ]

    confidentiality = any(k in text for k in confidentiality_keywords)
    integrity = any(k in text for k in integrity_keywords)

    encrypted = re.search(r"\bencrypted\b", text) is not None
    availability = any(k in text for k in availability_keywords) or encrypted

    if availability:
        primary_impact = "AVAILABILITY"
    elif confidentiality:
        primary_impact = "CONFIDENTIALITY"
    elif integrity:
        primary_impact = "INTEGRITY"
    else:
        primary_impact = "UNCLEAR - manual review needed"

    affected_count = sum([confidentiality, integrity, availability])
    severity = min(3, affected_count) if affected_count > 0 else 1

    return {
        "event": event.name,
        "confidentiality_affected": confidentiality,
        "integrity_affected": integrity,
        "availability_affected": availability,
        "primary_impact": primary_impact,
        "severity": severity,
        "severity_label": {1: "LOW", 2: "MEDIUM", 3: "HIGH"}[severity],
    }


def print_cia_report(events: List[SecurityEvent]) -> None:
    """Print a formatted CIA classification report."""
    print("\n" + "=" * 82)
    print("CIA TRIAD IMPACT CLASSIFICATION REPORT")
    print("=" * 82)
    print(f"{'EVENT':<30} {'C':^3} {'I':^3} {'A':^3} {'PRIMARY':<18} {'SEV':<6}")
    print("-" * 82)

    for event in events:
        result = classify_cia_impact(event)
        c_mark = "Y" if result["confidentiality_affected"] else "-"
        i_mark = "Y" if result["integrity_affected"] else "-"
        a_mark = "Y" if result["availability_affected"] else "-"

        print(
            f"{event.name[:29]:<30} "
            f"{c_mark:^3} {i_mark:^3} {a_mark:^3} "
            f"{result['primary_impact'][:17]:<18} "
            f"{result['severity_label']:<6}"
        )

    print("=" * 82)
    print("C=Confidentiality I=Integrity A=Availability")


def main() -> None:
    """Run the Week 1 assignment using the selected MedCore case company."""
    medcore = {
        "org_name": "MedCore Regional Hospital",
        "sector": "healthcare",
        "employees": 1200,
        "handles_health_data": True,
        "processes_payments": True,
        "handles_eu_personal_data": False,
        "public_company": False,
        "is_federal_contractor": False,
        "handles_cui": False,
        "california_presence": False,
        "has_ciso": False,
        "has_security_committee": True,
        "board_security_reporting": False,
        "security_budget_defined": True,
        "policy_suite_current": False,
        "has_risk_register": True,
        "annual_risk_assessment": True,
        "continuous_risk_monitoring": False,
        "risk_appetite_documented": False,
        "compliance_program": True,
        "last_audit_passed": True,
        "security_training": True,
        "vendor_risk_program": False,
    }

    print(generate_grc_summary_report(medcore))

    test_events = [
        SecurityEvent(
            "HealthBridge PHI Breach",
            "Attacker used credential stolen via spyware; 14,200 patient records data exposed to unauthorized party",
        ),
        SecurityEvent(
            "Hospital Ransomware Attack",
            "All systems encrypted by ransomware; EHR unavailable for 5 days",
        ),
        SecurityEvent(
            "EHR Record Tampering",
            "Nurse altered medication dosage records in EHR; patient harmed",
        ),
        SecurityEvent(
            "DDoS on Bank Portal",
            "Customer online banking portal unavailable for 6 hours via DDoS",
        ),
        SecurityEvent(
            "SQL Injection Attack",
            "Attacker injected SQL into web form; customer records altered",
        ),
        SecurityEvent(
            "Laptop Theft",
            "Unencrypted laptop with 3,000 employee SSNs stolen from car",
        ),
        SecurityEvent(
            "Insider Data Exfiltration",
            "Employee emailed 50,000 customer records to personal email before resignation",
        ),
        SecurityEvent(
            "Power Outage",
            "Data center power outage; no UPS; servers unavailable for 3 hours",
        ),
    ]

    print_cia_report(test_events)


if __name__ == "__main__":
    main()
