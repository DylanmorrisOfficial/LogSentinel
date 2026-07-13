from flask import Flask, render_template, request
from parser import parse_log

from detector import (
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failure,
)

from database import create_tables, save_logs, save_alerts, get_all_logs, get_all_alerts

create_tables()

# Creates the flask application
app = Flask(__name__, template_folder="../templates", static_folder="../static")


# Route for the homepage
@app.route("/")
def home():
    return render_template("index.html")


# Route for handling file uploads
@app.route("/upload", methods=["POST"])
def upload():
    # Check that the form included a file.
    if "logfile" not in request.files:
        return "No file uploaded", 400

    file = request.files["logfile"]

    # Check that the user selected a file.
    if file.filename == "":
        return "No file selected", 400

    file_path = "logs/uploaded.log"
    file.save(file_path)

    # Gets eeach entry in the uploaded file
    entries = parse_log(file_path)

    alerts = []

    # Checks for different attacks and stores them to alerts
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_password_spray(entries))
    alerts.extend(detect_success_after_failure(entries))

    save_logs(entries)
    save_alerts(alerts)

    return render_template(
        "dashboard.html",
        entries=entries,
        alerts=alerts,
    )


# Route for viewing the history of logs and alerts
@app.route("/history")
def history():
    # Gets all logs and alerts from the database
    logs = get_all_logs()
    alerts = get_all_alerts()

    return render_template(
        "history.html",
        logs=logs,
        alerts=alerts,
    )


# Main entry point for the application
if __name__ == "__main__":
    app.run(debug=True)
