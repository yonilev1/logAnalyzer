import checks
from collections import Counter, defaultdict
import config

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