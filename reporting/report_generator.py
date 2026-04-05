def generate_report(findings, score):
    print("\n=== OpenStack Security Report ===\n")

    if not findings:
        print("No security issues detected.")
    else:
        for f in findings:
            print(f"[{f['severity']}] {f['type']}")

    print("\n---")
    print(f"Overall Risk Score: {score}/100")

    if score >= 70:
        print("⚠️ Cloud Security Status: HIGH RISK")
    elif score >= 40:
        print("⚠️ Cloud Security Status: MEDIUM RISK")
    else:
        print("✅ Cloud Security Status: LOW RISK")