import sqlite3

DATABASE_NAME = "logsentinel.db"


def get_connection():
    # Returns a connection to the SQLite database
    return sqlite3.connect(DATABASE_NAME)


def create_tables():
    # Creates the necessary tables in the database if they do not already exist
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            user TEXT NOT NULL,
            ip TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            user TEXT NOT NULL,
            ip TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_logs(entries):
    # Saves the log entries to the database
    connection = get_connection()
    cursor = connection.cursor()

    for entry in entries:
        cursor.execute(
            """
            INSERT INTO logs (timestamp, event, user, ip)
            VALUES (?, ?, ?, ?)
        """,
            (str(entry.timestamp), entry.event, entry.user, entry.ip),
        )

    connection.commit()
    connection.close()


def save_alerts(alerts):
    # Saves the alerts to the database
    connection = get_connection()
    cursor = connection.cursor()

    for alert in alerts:
        cursor.execute(
            """
            INSERT INTO alerts (attack_type, severity, user, ip)
            VALUES (?, ?, ?, ?)
        """,
            (alert.alert_type, alert.severity, alert.user, alert.ip),
        )

    connection.commit()
    connection.close()


def get_all_logs():
    # Returns all log entries from the database
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, timestamp, event, user, ip
        FROM logs
        ORDER BY timestamp DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows


def get_all_alerts():
    # Returns all alerts from the database
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, attack_type, severity, user, ip
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows
