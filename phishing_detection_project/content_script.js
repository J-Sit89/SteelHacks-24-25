
let links = document.getElementsByTagName('a');  // Get all the links on the page

for (let i = 0; i < links.length; i++) {
    let link = links[i].href;
    
    chrome.runtime.sendMessage({
        action: 'checkLink',
        url: link
    }, function(response) {
        if (response.result === 1) {
            links[i].style.backgroundColor = 'red';  // Mark phishing link
            links[i].title = 'Warning: This link may be phishing!';
        } else {
            links[i].style.backgroundColor = 'green';  // Mark safe link
            links[i].title = 'This link is safe!';
        }
    });
}
