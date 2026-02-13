import checks
from collections import Counter, defaultdict
import config

number_of_lines = 0
number_of_suspicious_lines = 0
suspicion_counts = {
    "EXTERNAL_IP": 0,
    "LARGE_PACKET": 0,
    "SENSITIVE_PORT": 0,
    "NIGHT_ACTIVITY": 0
}


def update_count(rows_sus_list):
    global number_of_lines
    global number_of_suspicious_lines
    global suspicion_counts

    number_of_lines += 1
    if rows_sus_list:
        if len(rows_sus_list) > 0:
            number_of_suspicious_lines += 1

            for sus in rows_sus_list:
                if sus in suspicion_counts:
                    suspicion_counts[sus] += 1


def is_packet_normal(list_of_rows):
    large_rows = checks.extract_rows_over_5000_bytes(list_of_rows)
    packet_abnormality = ["LARGE" if row in large_rows else "NORMAL" for row in list_of_rows]
    return packet_abnormality


def count_ip_references(list_of_rows):
    count = Counter(row[1] for row in list_of_rows)
    return count


def port_number_to_name(list_of_rows):
    port_number_name = {row[3] : row[4] for row in list_of_rows}
    return port_number_name


def suspicion_recognition_for_ip(list_of_rows):
    external_ips = set(checks.extract_external_ip(list_of_rows))
    size_tags = is_packet_normal(list_of_rows)
    suspicion = defaultdict(set)

    for index, row in enumerate(list_of_rows):
        sus = set()
        if row[1] in external_ips:
            sus.add("EXTERNAL_IP")

        if size_tags[index] == "LARGE":
            sus.add("LARGE_PACKET")

        if row[3] in config.SENSITIVE_PORT:
            sus.add("SENSITIVE_PORT")

        hour = int(row[0][11:13])
        if 0 <= hour < 6:
            sus.add("NIGHT_ACTIVITY")

        suspicion[row[1]].update(sus)
    return suspicion


def get_all_ips_with_at_list_2_suspicion2(sus_map):
    at_list_2_suspicion2 = {key : value for key, value in sus_map.items() if len(value) >= 2}
    return at_list_2_suspicion2


def extract_hour(list_of_rows):
    hour = map(lambda x: int(x[0][11:13]), list_of_rows)
    return list(hour)


def convert_size_from_byte_to_kb(list_of_rows):
    kb = map(lambda x: int(x[5]) / 1024, list_of_rows)
    return list(kb)


def analyze_all_logs():
    suspicion_checks = {"EXTERNAL_IP": lambda row: not row[1].startswith(config.PRIVATE_IP_1) and not row[1].startswith(config.PRIVATE_IP_2),
                        "LARGE_PACKET": lambda row: int(row[5]) > 5000,
                        "SENSITIVE_PORT": lambda row: row[3] in config.SENSITIVE_PORT,
                        "NIGHT_ACTIVITY": lambda row: 0 <= int(row[0][11:13]) < 6}

    return suspicion_checks


def check_rows_suspicions(row, suspicion_checks):
    suspicious_names = filter(lambda key: suspicion_checks[key](row), suspicion_checks.keys())
    return list(suspicious_names)


def check_all_rows_suspicion_with_more_then_1(line_generator, suspicion_checks):
    for row in line_generator:
        if len(check_rows_suspicions(row, suspicion_checks)) > 0:
            yield row


def line_paired_with_suspicions(suspicious_generator, suspicion_checks):
    for row in suspicious_generator:
        suspicions = check_rows_suspicions(row, suspicion_checks)
        yield row, suspicions


def count_suspicious_lines(suspicion_generator):
    count = 0
    for row in suspicion_generator:
        count += 1
    return count
