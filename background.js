chrome.downloads.onChanged.addListener(async (downloadDelta) => {
    if (downloadDelta.state && downloadDelta.state.current === 'complete') {
        // Get the completed download item's details
        chrome.downloads.search({ id: downloadDelta.id }, async (downloadItems) => {
            if (downloadItems && downloadItems.length > 0) {
                const downloadItem = downloadItems[0];

                // File path for the downloaded file
                const filePath = downloadItem.filename;
                await chrome.action.openPopup();
                chrome.runtime.sendMessage({
                    action: 'scanInProgress',
                    fileName: filePath
                });


                try {
                    // Read the downloaded file as a Blob
                    const fileBlob = await readFileAsBlob(filePath, downloadItem);

                    // Calculate the SHA-256 hash of the downloaded file
                    const fileHash = await calculateFileHash(fileBlob);
                    console.log('The file hash : ', fileHash);

                    // Scan the file hash with VirusTotal and MetaDefender
                    const scanResults = await scanFile(fileHash, filePath, fileBlob);

                    // Handle the scan results (e.g., show a notification)
                    console.log('Scan Results:', scanResults);

                    if (scanResults === false) {
                        console.log('The file you downloaded might be dangerous. Please take caution!');
                        showNotification('Warning: Suspicious File Detected', 'The file you downloaded might be dangerous. Please take caution!', false);
                        chrome.runtime.sendMessage({
                            action: 'scanComplete',
                            status: 'danger'
                        });
                    } else {
                        if (scanResults === true) {
                            console.log('The file you downloaded is safe. No threats detected!');
                            showNotification('Scan Complete: No Threats Detected', 'The file you downloaded is safe.', true);
                            chrome.runtime.sendMessage({
                                action: 'scanComplete',
                                status: 'safe'
                            });
                        } else {
                            if (scanResults === null) {
                                console.log('The file you downloaded could not be scanned ,or exceeded file size limit. Please try again later!');
                                showNotification('Scan Failed', 'The file you downloaded could not be scanned or exceeded file size limit.', false);
                                chrome.runtime.sendMessage({
                                    action: 'scanComplete',
                                    status: 'error'
                                });
                            }
                        }
                    }
                } catch (error) {
                    console.error('Error reading or scanning file:', error);
                }
            }
        });
    }
});
// Read a file from disk as a Blob
async function readFileAsBlob(filePath, downloadItem) {
    return new Promise((resolve, reject) => {
        // Fetch the file from its URL
        console.log('The download item : ', downloadItem.url);
        fetch(downloadItem.url)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to fetch file from URL: ${downloadItem.url}`);
                }
                return response.blob();  // Convert the response to a Blob
            })
            .then(blob => resolve(blob))
            .catch(error => reject(error));
    });
}
// Calculate the SHA-256 hash of a file blob
async function calculateFileHash(fileBlob) {
    const arrayBuffer = await fileBlob.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}
// SFunction to scan file hash using VirusTotal and MetaDefender
async function scanFile(fileHash, filePath, fileBlob) {
    const apiKeyVirusTotal = 'Our API Key';
    const apiKeyMeta = 'Our API Key';
    try {
        const virusTotalResult = await scanVirusTotal(fileHash, apiKeyVirusTotal, filePath, fileBlob)
            .catch(error => {
                console.error('VirusTotal scan failed:', error);
                return null;  // Handle VirusTotal failure
            });
        const metaResult = await scanMeta(fileHash, apiKeyMeta, filePath, fileBlob)
            .catch(error => {
                console.error('MetaDefender scan failed:', error);
                return null;  // Handle MetaDefender failure
            });


        console.log('VirusTotal Result: ', virusTotalResult);
        console.log('MetaDefender Result: ', metaResult);
        if (virusTotalResult === null) {
            return metaResult;
        } else {
            if (metaResult === null) {
                return virusTotalResult;
            } else {
                return virusTotalResult && metaResult;
            }
        }
    }
    catch (error) {
        console.error('Error during scanFile:', error);
        return null;  // Return null in case of error
    }
}
// Scan file hash using VirusTotal
async function scanVirusTotal(fileHash, apiKey, filePath, fileBlob) {
    const reportUrl = `https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${fileHash}`;
    console.log('gfgfgf');

    try {
        const response = await fetch(reportUrl);
        const data = await response.json();

        // If the file is not found in VirusTotal's database, upload the file for scanning
        if (data.response_code === 0) {
            console.log('File not found in VirusTotal database.');
            console.log('Uploading file to VirusTotal...');
            return await uploadFileToVirusTotal(filePath, apiKey, fileBlob);
        }
        console.log(data);
        return data.response_code === 1; // Return the scan results
    } catch (error) {
        console.error('Error in VirusTotal scan:', error);
        return null; // Return null in case of error
    }
}
// Upload the downloaded file to VirusTotal
async function uploadFileToVirusTotal(filePath, apiKey, fileBlob) {
    try {
        const formData = new FormData();
        formData.append('file', fileBlob);
        formData.append('apikey', apiKey);
        const filesizemin = 32 * 1024 * 1024;
        if (fileBlob.size < filesizemin) {
            console.log('less than 32 : ', fileBlob.size);
            const uploadUrl = `https://www.virustotal.com/vtapi/v2/file/scan`;
            const response = await fetch(uploadUrl, {
                method: 'POST',
                body: formData,
            });
            console.log('The response : ', response);
            const result = await response.json();
            console.log('File uploaded to VirusTotal:', result);
            console.log(result);
            return result.response_code === 1; // Return the scan results
        } else {
            console.error('File too large to upload to VirusTotal.');
            return null; // Skip the upload
        }
    } catch (error) {
        console.error('Error uploading file to VirusTotal:', error);
        return null; // Return null in case of error
    }
}
// Scan file hash using MetaDefender
async function scanMeta(fileHash, apiKey, filePath, fileBlob) {
    const reportUrl = `https://api.metadefender.com/v4/file/${fileHash}`;
    const url = 'https://api.metadefender.com/v4'
    try {
        const response = await fetch(reportUrl, {
            headers: {
                'apikey': apiKey,
            },
        });

        const data = await response.json();
        console.log('MetaDefender Scan result: // before uploading ', data);
        if (data.scan_results) {
            console.log('MetaDefender Scan result:', data);
            if (data.scan_results.scan_all_result_a === 'No Threat Detected') {
                return true; // Return the scan results
            } else {
                return false; // Return the scan results
            }
        } else {
            console.log('The file is not found in MetaDefender database.');
            console.log('Uploading the file ...');
            return await uploadFileToMetaDefender(fileBlob, apiKey);

        }
    } catch (err) {
        console.error('Error scanning the file with MetaDefender:', err);
        return null; // Return null in case of error
    }
}
async function uploadFileToMetaDefender(fileBlob, apiKey) {
    const formData = new FormData();
    formData.append('file', fileBlob);

    const uploadUrl = 'https://api.metadefender.com/v4/file';

    try {
        const response = await fetch(uploadUrl, {
            method: 'POST',
            headers: {
                'apikey': apiKey,
            },
            body: formData,
        });

        const result = await response.json();
        console.log('File upload response:', result);
        const uploadId = result.data_id;
        return await checkScanStatus(uploadId, apiKey);

    } catch (err) {
        console.error('Error uploading file to MetaDefender:', err);
        return null;
    }
}
async function checkScanStatus(uploadId, apiKey) {
    const url = `https://api.metadefender.com/v4/file/${uploadId}`;

    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'apikey': apiKey,
            },
        });

        const data = await response.json();
        console.log('MetaDefender Scan status:', data);
        if (data.scan_results.progress_percentage === 100) {
            if (data.scan_results.scan_all_result_a === 'No Threat Detected') {
                return true; // Return the scan results
            } else {
                return false; // Return the scan results
            }
        }
        while (data.scan_results.progress_percentage < 100) {
            console.log('Scan in progress...');
            await new Promise(resolve => setTimeout(resolve, 5000)); // Wait for 5 seconds
            return await checkScanStatus(uploadId, apiKey);
        }
    } catch (err) {
        console.error('Error checking the scan status with MetaDefender:', err);
        return null; // Return null in case of error
    }
}
function showNotification(title, message, VirusDetected) {

    const iconUrl = VirusDetected ? 'icons/safe.png' : 'icons/danger.png';


    chrome.notifications.create({
        type: 'basic',
        iconUrl: iconUrl,
        title: title,
        message: message,
        priority: 2
    }, function (notificationId) {
        console.log('Notification displayed with ID:', notificationId);
    });
}

const checkedUrls = new Set();
chrome.webRequest.onCompleted.addListener(
    function (details) {
        try {
            const url = details.url;
            const baseUrl = getBaseUrl(url);
            console.log(`Checking base URL: ${baseUrl}`);
            return checkUrl(baseUrl);

        } catch (error) {
            console.log('Error while checking URL:', error);
        }


    }, {
    urls: ["<all_urls>"],
    types: ["main_frame"]
});
async function checkUrl(url) {
    const apiKey = 'Our API Key';
    const apiUrl = 'https://www.virustotal.com/vtapi/v2/url/report';

    const params = new URLSearchParams({
        apikey: apiKey,
        resource: url
    });

    try {
        const response = await fetch(`${apiUrl}?${params.toString()}`);
        const data = await response.json();
        console.log('The data : ', data);
        if (data.response_code === 1 && data.positives > 0) {
            // Unsafe site 
            showNotification('Unsafe Website Detected', `The website you are visiting (${url}) has been flagged by VirusTotal.`, false);
        } else if (data.response_code === 1 && data.positives === 0) {
            // Safe site
            console.log(`The website ${url} is safe.`);
        } else {
            showNotification('Unknown website', `Please be careful entering the website (${url}).`, false);
            console.error('No information found for this URL.');
        }
    } catch (error) {
        console.error('Error while checking URL with VirusTotal:', error);
    }
}


function getBaseUrl(url) {
    try {
        const urlObj = new URL(url);
        return `${urlObj.protocol}//${urlObj.hostname}/`;
    } catch (error) {
        console.error('Invalid URL:', url);
        return url;  // Return the original URL if parsing fails
    }
}