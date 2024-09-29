function sendUrlToApi(url, callback) {
    fetch('http://127.0.0.1:5000/analyze_link', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })  // Send URL to Flask API
    })
    .then(response => response.json())
    .then(data => {
        callback(data.phishing);  // Get the result (0 or 1)
    })
    .catch(error => {
        console.error('Error:', error);
    });
  }
  
  // Listen for messages from content_script.js
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkLink') {
        sendUrlToApi(message.url, (result) => {
            sendResponse({ result: result });
        });
        return true;  // Keeps the response channel open
    }
  });