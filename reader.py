import csv
import pathlib

def read_log_file(log_file_path):
    row_list = []
    with open(log_file_path, 'r') as log_file:
        log_reader = csv.reader(log_file, delimiter=',')
        for row in log_reader:
            row_list.append(row)
    return row_list
