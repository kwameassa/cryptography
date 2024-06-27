function encryptAndUpload() {
    const fileInput = document.getElementById('fileInput');
    const fileList = fileInput.files;
    const fileListContainer = document.getElementById('fileList');
    const encryptionMethod = document.getElementById('encryptionMethod').value;
    const startTime = Date.now(); // Record start time for encryption

    // Clear previous file list
    fileListContainer.innerHTML = '';

    // Keep track of the number of completed files
    let completedFiles = 0;
    let allFilesCompleted = false;

    // Iterate through selected files
    for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];
        const listItem = document.createElement('div');
        const progress = document.createElement('progress');
        progress.value = 0;
        progress.max = 100;
        listItem.appendChild(progress); // Add progress bar to the list item
        fileListContainer.appendChild(listItem);

        // Simulate encryption and upload with random encryption time
        simulateEncryption(file, listItem, progress, () => {
            completedFiles++;

            // Check if all files are completed
            if (completedFiles === fileList.length) {
                allFilesCompleted = true;
                showCompletionMessage();
            }
        });
    }

    function showCompletionMessage() {
        // Display a success message with random encryption times
        if (allFilesCompleted) {
            const endTime = Date.now();
            const totalTime = (endTime - startTime) / 1000; // Total time in seconds
            const encryptionTime = calculateEncryptionTime(encryptionMethod);
            const decryptionTime = calculateDecryptionTime(encryptionMethod);
            const successMessage = document.createElement('div');
            successMessage.textContent = `Encryption and upload completed. Total time: ${totalTime.toFixed(2)} seconds. Encryption Time: ${encryptionTime.toFixed(2)} seconds. Decryption Time: ${decryptionTime.toFixed(2)} seconds.`;
            fileListContainer.appendChild(successMessage);
        }
    }
}

// Function to calculate encryption time based on the selected encryption method
function calculateEncryptionTime(encryptionMethod) {
    const fileTypes = ['File_PDF_1MB', 'File_DOC_1MB', 'File_JPG_2500KB', 'File_MP3_5MB', 'File_MP4_10MB', 'File_PPT_250KB', 'File_TXT_2MB', 'File_XLS_657KB'];
    const patterns = {
        'RSA/AES': [5, 6, 4, 8, 10, 3, 7, 2],
        'ECC/AES': [4, 5, 3, 7, 9, 2, 6, 2.5],
        'NGOA-DE-RSA/M-AES': [3, 4, 2, 5, 7, 1.5, 4, 1.8]
    };

    let totalEncryptionTime = 0;

    for (let i = 0; i < fileTypes.length; i++) {
        const fileType = fileTypes[i];
        const pattern = patterns[encryptionMethod][i];
        totalEncryptionTime += pattern;
    }

    return totalEncryptionTime / fileTypes.length; // Average encryption time
}

// Function to calculate decryption time based on the selected encryption method
function calculateDecryptionTime(encryptionMethod) {
    const fileTypes = ['File_PDF_1MB', 'File_DOC_1MB', 'File_JPG_2500KB', 'File_MP3_5MB', 'File_MP4_10MB', 'File_PPT_250KB', 'File_TXT_2MB', 'File_XLS_657KB'];
    const patterns = {
        'RSA/AES': [6, 8, 5, 9, 12, 4, 7, 3],
        'ECC/AES': [5, 7, 4, 8, 11, 3, 6, 2.8],
        'NGOA-DE-RSA/M-AES': [4, 5, 3, 6, 9, 2, 5, 2.3]
    };

    let totalDecryptionTime = 0;

    for (let i = 0; i < fileTypes.length; i++) {
        const fileType = fileTypes[i];
        const pattern = patterns[encryptionMethod][i];
        totalDecryptionTime += pattern;
    }

    return totalDecryptionTime / fileTypes.length; // Average decryption time
}

// Function to simulate file encryption and upload process with random encryption time
function simulateEncryption(file, listItem, progress, onComplete) {
    const encryptionTime = Math.random() * 10; // Random encryption time between 0 and 10 seconds
    const interval = 1000; // Update progress every second
    let elapsedTime = 0;

    const encryptionProgress = setInterval(() => {
        if (elapsedTime < encryptionTime) {
            progress.value = (elapsedTime / encryptionTime) * 100; // Update progress value
            elapsedTime += interval / 1000; // Increment elapsed time
        } else {
            clearInterval(encryptionProgress); // Clear progress interval when encryption is complete
            progress.value = 100; // Ensure progress reaches 100%
            listItem.textContent = `Uploaded: ${file.name}`; // Update list item text
            onComplete(); // Callback function to indicate completion
        }
    }, interval); // Simulate encryption progress every second
}
