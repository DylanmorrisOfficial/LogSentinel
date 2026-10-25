# LogSentinel

LogSentinel is a Python-based Security Information and Event Management (SIEM) project designed to analyse authentication logs, detect suspicious login activity and help investigate potential security incidents.

The project uses rule-based detection to identify brute-force attacks, password spraying and successful logins following repeated failures. A Flask web dashboard displays security events, with SQLite providing persistent storage for logs and alerts.

## Features

- **Log parsing and validation:** Parses log data and validates input, including handling invalid data and edge cases.
- **Brute-force detection:** Identifies repeated failed login attempts using a five-minute sliding window.
- **Severity levels:** Assigns severity levels to brute-force activity based on failed login attempts.
- **Password-spraying detection:** Identifies suspicious login attempts targeting multiple accounts.
- **Suspicious login detection:** Detects successful logins following repeated failed attempts.
- **Web dashboard:** Uses Flask, HTML, CSS and JavaScript to display security analysis results.
- **Persistent storage:** Stores security logs and alerts in an SQLite database.
- **Log and alert history:** Provides a history page for reviewing previously stored events and alerts.
- **Automated testing:** Includes unit tests for log parsing and detection logic.

## Technologies

- **Language:** Python
- **Web framework:** Flask
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript
- **Testing:** Python unit tests

## How It Works

LogSentinel processes authentication log data and applies detection rules to identify suspicious behaviour.

1. **Parse:** Read and validate log data.
2. **Analyse:** Apply detection rules to identify suspicious authentication patterns.
3. **Classify:** Assign severity levels where supported by the detection rules.
4. **Store:** Save logs and alerts in SQLite.
5. **Investigate:** View security events and historical alerts through the web dashboard.

## Project Structure

The application is organised into separate components for log parsing, detection logic, data storage, the web interface and testing.

See the repository files for the current implementation.

## Future Improvements

- Add filtering and search by username, source IP, severity and time range.
- Build