import analyzer

def generate_report(suspicious_dict):
    three_sus = {}
    for key, value in suspicious_dict.items():
        if len(value) > 2:
            three_sus[key] = value


    print("General Statistics:")
    print(f"-Number of lines: {analyzer.number_of_lines}")
    print(f"-Number of suspicious lines: {analyzer.number_of_suspicious_lines}")
    print(f"-Number of EXTERNAL_IP events: {analyzer.suspicion_counts['EXTERNAL_IP']}")
    print(f"-Number of LARGE_PACKET events: {analyzer.suspicion_counts['LARGE_PACKET']}")
    print(f"-Number of SENSITIVE_PORT events: {analyzer.suspicion_counts['SENSITIVE_PORT']}")
    print(f"-Number of NIGHT_ACTIVITY events: {analyzer.suspicion_counts['NIGHT_ACTIVITY']}")

    print("IPs with high level risk (3+ suspicions):")
    for key, value in three_sus.items():
        print(f"{key}: {value}")
