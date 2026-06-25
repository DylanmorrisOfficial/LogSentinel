from flask import Flask, render_template, request

# Creates the flask application
app = Flask(__name__, template_folder="../templates")


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

    file.save("logs/uploaded.log")
    return "File received"


# Main entry point for the application
if __name__ == "__main__":
    app.run(debug=True)
