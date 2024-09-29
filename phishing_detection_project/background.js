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
        callback(data.phishing, data.gemini_analysis);  // Pass both phishing result and Gemini analysis
    })
    .catch(error => {
        console.error('Error:', error);
        callback(null, null);  // Indicate an error occurred
    });
}

// Listen for messages from content_script.js
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkLink') {
        sendUrlToApi(message.url, (result, geminiAnalysis) => {
            if (result !== null) {
                sendResponse({ result: result, gemini_analysis: geminiAnalysis });
            } else {
                sendResponse({ result: -1, gemini_analysis: "Error analyzing link." });  // Error indicator
            }
        });
        return true;  // Keeps the response channel open
    }
});
