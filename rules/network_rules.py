def check_network_rules(data):
    findings = []

    for rule in data["rules"]:
        remote_ip = getattr(rule, "remote_ip_prefix", None)
        protocol = getattr(rule, "protocol", None)
        port_min = getattr(rule, "port_range_min", None)
        port_max = getattr(rule, "port_range_max", None)

        # 🚨 Public SSH
        if remote_ip == "0.0.0.0/0" and protocol == "tcp" and port_min == 22:
            findings.append({
                "type": "Public SSH",
                "severity": "HIGH"
            })

        # 🚨 Public RDP
        if remote_ip == "0.0.0.0/0" and protocol == "tcp" and port_min == 3389:
            findings.append({
                "type": "Public RDP",
                "severity": "HIGH"
            })

        # 🚨 Database Ports
        if remote_ip == "0.0.0.0/0" and protocol == "tcp" and port_min in [3306, 5432, 1433]:
            findings.append({
                "type": "Public Database Port",
                "severity": "CRITICAL"
            })

        # 🚨 All ports open
        if remote_ip == "0.0.0.0/0" and protocol is None:
            findings.append({
                "type": "All Ports Open",
                "severity": "CRITICAL"
            })

    return findings