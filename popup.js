// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const fileNameElement = document.getElementById('fileName');
    const messageElement = document.getElementById('message');
    const resultElement = document.getElementById('result');

    if (message.action === 'scanInProgress') {
        fileNameElement.innerText = `Scanning file: ${message.fileName}`;
        messageElement.innerText = 'Please wait, scanning in progress...';
        resultElement.classList.remove('success', 'danger', 'warning');
    }

    if (message.action === 'scanComplete') {
        if (message.status === 'safe') {
            messageElement.innerText = 'The file is safe to use!';
            resultElement.innerText = 'No threats detected';
            resultElement.classList.add('success');
        } else if (message.status === 'danger') {
            messageElement.innerText = 'Warning: Suspicious file detected!';
            resultElement.innerText = 'Threats detected. Be cautious!';
            resultElement.classList.add('danger');
        } else if (message.status === 'error') {
            messageElement.innerText = 'Scan failed. Please try again later.';
            resultElement.innerText = 'Unable to scan the file.';
            resultElement.classList.add('warning');
        }
    }
});
