import checks
import csv
import pathlib
import reader
from collections import Counter

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
    #count = {row[1] : 1 for row in list_of_rows}
    count = Counter(row[1] for row in list_of_rows)
    return count


def port_number_to_name(log_list):
    port_number_name = {row[3] : row[4] for row in log_list}
    return port_number_name








