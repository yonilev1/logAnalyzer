import config
import reader
import csv
import pathlib
def extract_external_ip(log_list):
    external_ip_list = [row[1] for row in log_list if not str(row[1]).startswith(config.PRIVATE_IP_1) and not str(row[1]).startswith(config.PRIVATE_IP_2)]
    return external_ip_list


def extract_suspicious_ports(log_list):
    suspicious_ports = [row for row in log_list if row[3] in config.SENSITIVE_PORT]
    return suspicious_ports


def extract_rows_over_5000_bytes(log_list):
    overload_row_list = [row for row in log_list if int(row[5]) > config.LARGE_PACKET]
    return overload_row_list


def filter_all_logs_with_sensitive_ports(log_list):
    sensitive_ports = filter(lambda x: x[3] in config.SENSITIVE_PORT, log_list)
    return list(sensitive_ports)


def filter_night_activity(log_list):
    night_activity = filter(lambda x: 0 <= int(x[0][11:13]) < 6, log_list)
    return list(night_activity)

