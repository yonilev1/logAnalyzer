import checks
import csv
import pathlib
import reader

def is_packet_normal(list_of_rows):
    packet_abnormality = []
    large_rows = checks.extract_rows_over_5000_bytes(list_of_rows)
    for row in list_of_rows:
        if row in large_rows:
            packet_abnormality.append("LARGE")
        else:
            packet_abnormality.append("NORMAL")
    return packet_abnormality








