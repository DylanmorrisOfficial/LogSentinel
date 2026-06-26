lucide.createIcons();


const fileInput = document.getElementById("logfile");
const fileName = document.getElementById("file-name");

// Checks that both elements exist before adding an event listener.
if (fileInput && fileName) {
    // Calls updateFileName() whenever the user selects a file.
    fileInput.addEventListener("change", updateFileName);
}

/**
 * Updates the displayed file name after the user selects a file.
 */
function updateFileName() {

    // Checks if at least one file has been selected.
    if (fileInput.files.length > 0) {

        // Displays the name of the first selected file.
        fileName.textContent = fileInput.files[0].name;

    } else {

        // Displays the default message if no file is selected.
        fileName.textContent = "No file selected";

    }
}