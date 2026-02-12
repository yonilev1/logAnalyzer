import config
import reader
import csv
import pathlib
def extract_external_ip(log_list):
    external_ip_list = []
    for row in log_list:
        if not str(row[1]).startswith(config.PRIVATE_IP_1) and not str(row[1]).endswith(config.PRIVATE_IP_2):
            external_ip_list.append(row[1])

    return external_ip_list


def extract_suspicious_ports(log_list):
    suspicious_ports = []
    for row in log_list:
        if row[3] in config.SENSITIVE_PORT:
            suspicious_ports.append(row)
    return suspicious_ports


def extract_rows_over_5000_bytes(log_list):
    overload_row_list = []
    for row in log_list:
        if int(row[5]) > config.LARGE_PACKET:
            overload_row_list.append(row)
    return overload_row_list
