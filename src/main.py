from parser import parse_log


def main():
    # Gets the sammple log file and parses it
    log_file_path = "../logs/sample.log"
    log_entries = parse_log(log_file_path)

    # Displays each entry in the file
    for entry in log_entries:
        print(entry)


# Main entry point for the Application
if __name__ == "__main__":
    main()
