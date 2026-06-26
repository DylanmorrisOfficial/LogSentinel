from flask import Flask, render_template, request
from parser import parse_log
from detector import detect_brute_force, detect_password_spray

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

    return render_template(
        "dashboard.html",
        entries=entries,
        alerts=alerts,
    )


# Main entry point for the application
if __name__ == "__main__":
    app.run(debug=True)
