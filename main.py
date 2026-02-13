import reader
import pathlib
import checks
from analyzer import *
from reporter import *


def main():
    suspicious = log_analyzer("network_traffic.log")
    report = generate_report(suspicious)
    print(report)
    save_report(report, "security_report.txt")


if __name__ == "__main__":
    main()