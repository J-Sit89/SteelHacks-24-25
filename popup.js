document.getElementById('checkUrl').addEventListener('click', () => {
  let url = document.getElementById('url').value;

  chrome.runtime.sendMessage({
    action: 'checkLink',
    url: url
  }, function(response) {
    if (response.result === 1) {
      document.getElementById('result').textContent = 'Phishing detected!';
      document.getElementById('result').style.color = 'red';
    } else {
      document.getElementById('result').textContent = 'Safe link.';
      document.getElementById('result').style.color = 'green';
    }
  });
});