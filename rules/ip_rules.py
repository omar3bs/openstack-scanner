def check_ip_rules(data):
    findings = []

    for ip in data["floating_ips"]:
        if not ip.fixed_ip_address:
            findings.append({
                "type": "Orphaned Floating IP",
                "severity": "LOW"
            })

    return findings