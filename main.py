def main():
    print("\n🚀 Starting OpenStack Security Scanner...\n")

    conn = get_connection()
    data = collect_data(conn)

    findings = []
    findings += check_network_rules(data)
    findings += check_ip_rules(data)
    findings += check_storage_rules(data)

    score = calculate_score(findings)

    generate_report(findings, score)