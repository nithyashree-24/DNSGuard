import re
import math
from collections import Counter, defaultdict


LOG_FILE = "sample_dns_logs.txt"


def calculate_entropy(text):
    if not text:
        return 0

    counts = Counter(text)
    length = len(text)

    entropy = 0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_dns_logs():
    domain_counts = Counter()
    client_counts = Counter()
    nxdomain_counts = Counter()
    suspicious_domains = defaultdict(list)

    total_queries = 0

    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                query_match = re.search(r"query=([^\s]+)", line)
                client_match = re.search(r"client=([^\s]+)", line)
                status_match = re.search(r"status=([^\s]+)", line)

                if not query_match:
                    continue

                domain = query_match.group(1)
                client = client_match.group(1) if client_match else "Unknown"
                status = status_match.group(1) if status_match else "UNKNOWN"

                total_queries += 1
                domain_counts[domain] += 1
                client_counts[client] += 1

                if status.upper() == "NXDOMAIN":
                    nxdomain_counts[domain] += 1

                labels = domain.split(".")
                longest_label = max(labels, key=len)

                entropy = calculate_entropy(longest_label)

                risk_score = 0
                reasons = []

                if len(longest_label) >= 20:
                    risk_score += 30
                    reasons.append("Long DNS label")

                if entropy >= 3.5:
                    risk_score += 30
                    reasons.append("High entropy")

                if domain_counts[domain] >= 5:
                    risk_score += 20
                    reasons.append("High query frequency")

                if status.upper() == "NXDOMAIN":
                    risk_score += 20
                    reasons.append("NXDOMAIN response")

                risk_score = min(risk_score, 100)

                if risk_score >= 50:
                    suspicious_domains[domain] = {
                        "client": client,
                        "entropy": entropy,
                        "risk_score": risk_score,
                        "reasons": reasons
                    }

    except FileNotFoundError:
        print("\n[ERROR] sample_dns_logs.txt not found.")
        print("Create the sample log file before running DNSGuard.")
        return

    print("\n" + "=" * 55)
    print("                 DNSGUARD")
    print("        DNS Threat Detection Engine")
    print("=" * 55)

    print(f"\nTotal DNS Queries : {total_queries}")
    print(f"Unique Domains   : {len(domain_counts)}")
    print(f"Unique Clients   : {len(client_counts)}")
    print(f"Suspicious Domains: {len(suspicious_domains)}")

    print("\n" + "-" * 55)
    print("THREAT ANALYSIS")
    print("-" * 55)

    if not suspicious_domains:
        print("\nNo suspicious DNS activity detected.")

    for domain, data in suspicious_domains.items():
        print(f"\nDomain      : {domain}")
        print(f"Client      : {data['client']}")
        print(f"Entropy     : {data['entropy']:.2f}")
        print(f"Risk Score  : {data['risk_score']}/100")
        print("Threat      : POSSIBLE DNS TUNNELING / SUSPICIOUS ACTIVITY")
        print("Indicators  : " + ", ".join(data["reasons"]))

    print("\n" + "=" * 55)
    print("DNSGuard analysis completed.")
    print("=" * 55)


if __name__ == "__main__":
    analyze_dns_logs()
