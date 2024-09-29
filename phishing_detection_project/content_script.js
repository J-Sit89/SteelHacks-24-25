(function() {
    const analyzedLinks = new Set();

    function analyzeLinkElement(linkElement) {
        if (analyzedLinks.has(linkElement)) {
            // Link already analyzed; skip it
            return;
        }
        analyzedLinks.add(linkElement);

        let link = linkElement.href;

        chrome.runtime.sendMessage({
            action: 'checkLink',
            url: link
        }, function(response) {
            if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError);
                linkElement.style.backgroundColor = 'yellow';
                linkElement.title = 'Error checking this link.';
            } else if (response && response.result === 1) {
                linkElement.style.backgroundColor = 'red';  // Mark phishing link
                linkElement.title = 'Warning: This link may be phishing!';
            } else if (response && response.result === 0) {
                linkElement.style.backgroundColor = 'transparent';
                linkElement.title = 'This link is safe.';
            } else {
                // Unexpected response or error
                linkElement.style.backgroundColor = 'yellow';
                linkElement.title = 'Unable to verify this link.';
            }
        });
    }

    function analyzeLinksInNode(node) {
        if (node.nodeName.toLowerCase() === 'a') {
            analyzeLinkElement(node);
        } else {
            let links = node.getElementsByTagName('a');
            for (let i = 0; i < links.length; i++) {
                analyzeLinkElement(links[i]);
            }
        }
    }

    function processMutations(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                mutation.addedNodes.forEach(function(node) {
                    analyzeLinksInNode(node);
                });
            }
        });
    }

    // Initial analysis of existing links
    analyzeLinksInNode(document.body);

    // Set up MutationObserver to monitor added nodes
    const observer = new MutationObserver(processMutations);
    observer.observe(document.body, { childList: true, subtree: true });
})();
