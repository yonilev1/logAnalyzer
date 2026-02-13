import analyzer


def generate_report(suspicious_dict):
    three_sus = {}
    other_sus = {}

    for key, value in suspicious_dict.items():
        if len(value) > 2:
            three_sus[key] = value
        else:
            other_sus[key] = value

    report = "==============================\n"
    report += "      דוח תעבורה חשודה\n"
    report += "==============================\n\n"

    report += "General Statistics:\n"
    report += f"- Number of lines: {analyzer.number_of_lines}\n"
    report += f"- Number of suspicious lines: {analyzer.number_of_suspicious_lines}\n"
    report += f"- EXTERNAL_IP events: {analyzer.suspicion_counts['EXTERNAL_IP']}\n"
    report += f"- LARGE_PACKET events: {analyzer.suspicion_counts['LARGE_PACKET']}\n"
    report += f"- SENSITIVE_PORT events: {analyzer.suspicion_counts['SENSITIVE_PORT']}\n"
    report += f"- NIGHT_ACTIVITY events: {analyzer.suspicion_counts['NIGHT_ACTIVITY']}\n\n"

    report += "IPs with high level risk (3+ suspicions):\n"
    for key, value in three_sus.items():
        sus_str = ", ".join(value)
        report += f"- {key}: {sus_str}\n"

    report += "\nAdditional suspicious IPs:\n"
    for key, value in other_sus.items():
        sus_str = ", ".join(value)
        report += f"- {key}: {sus_str}\n"

    return report


def save_report(report, file_path):
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(report)
        f.write("\n")

