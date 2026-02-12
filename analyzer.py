import checks
import csv
import pathlib
import reader
from collections import Counter
from datetime import datetime
import config

def is_packet_normal(list_of_rows):
    packet_abnormality = []
    large_rows = checks.extract_rows_over_5000_bytes(list_of_rows)
    for row in list_of_rows:
        if row in large_rows:
            packet_abnormality.append("LARGE")
        else:
            packet_abnormality.append("NORMAL")
    return packet_abnormality


def count_ip_references(list_of_rows):
    count = Counter(row[1] for row in list_of_rows)
    return count


def port_number_to_name(list_of_rows):
    port_number_name = {row[3] : row[4] for row in list_of_rows}
    return port_number_name


def suspicion_recognition_for_ip(list_of_rows):
    external_ips = checks.extract_external_ip(list_of_rows)
    ports = port_number_to_name(list_of_rows)
    size_of_packet = is_packet_normal(list_of_rows)
    suspicion = {}
    for index, row in enumerate(list_of_rows):
        sus = []
        if row[1] in external_ips:
            sus.append("EXTERNAL_IP")

        if size_of_packet[index] == "LARGE":
            sus.append("LARGE_PACKET")

        if row[3] in config.SENSITIVE_PORT:
            sus.append("SENSITIVE_PORT")

        dt_object = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")

        if 0 <= dt_object.hour < 6:
            sus.append("NIGHT_ACTIVITY")

        if row[1] not in suspicion.keys():
            suspicion[row[1]] = sus
        else:
            if len(suspicion[row[1]]) < len(sus):
                suspicion[row[1]] = sus
            elif len(suspicion[row[1]]) == len(sus):
                if suspicion[row[1]] != sus:
                    sus += suspicion[row[1]]
                    sus = set(sus)
                    suspicion[row[1]] = list(sus)
    return suspicion


def get_all_ips_with_at_list_2_suspicion2(sus_map):
    at_list_2_suspicion2 = {}
    for key, value in sus_map.items():
        if len(value) >= 2:
            at_list_2_suspicion2[key] = value
    return at_list_2_suspicion2







