function sendUrlToApi(url, callback) {
    fetch('http://127.0.0.1:5000/analyze_link', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        callback(data.phishing);
    })
    .catch(error => {
        console.error('Error:', error);
        callback(null);  // Indicate an error occurred
    });
}

// Listen for messages from content_script.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkLink') {
        sendUrlToApi(message.url, (result) => {
            if (result !== null) {
                sendResponse({ result: result });
            } else {
                sendResponse({ result: -1 });  // Error indicator
            }
        });
        return true;  // Keeps the response channel open
    }
});
