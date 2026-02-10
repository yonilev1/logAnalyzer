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
        if row[3] in config.SENSITIVE_PORTS:
            suspicious_ports.append(row)
    return suspicious_ports
