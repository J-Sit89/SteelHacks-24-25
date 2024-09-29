# Gone Phishing
**Team Members:** Logan Warren, Josh Sitler

## Inspiration
...
#Over the past few semesters, we have recieved email upon email from Pitt IT about the dangers of phishing emails.  While some people can eyeball the links to see if they're sketchy, some cannot.  We were inspired to make something where the ability to just take a look at links to determine if they're phishing links or not is handeled by an AI.

## What it does
...
This extension is designed to help users protect themselves from phishing attacks by analyzing URLs found in emails. It works by extracting over 50 different features from each URL, including the number of special characters like dots, hyphens, and slashes, the length of the URL, and whether the domain is an IP address. These features are used to detect suspicious patterns commonly found in phishing links.  It also utilizes Gemini to read an inputted link on our website to see if it is dangerous or not.

## How we built it
...
Gone Phishing uses a Flask backend with a machine learning model trained to recognize phishing URLs. When a link is analyzed, it compares the extracted features to those of known phishing sites and returns a prediction indicating whether the link is safe or not. Additionally, the extension includes a whitelist of trusted domains like microsoft.com and google.com, ensuring that links from these sites are automatically marked as safe.

The detection engine for the pluggin uses a joblib-pickled machine learning pipeline that applies advanced feature extraction techniques to URLs and provides real-time phishing detection. This ensures users are protected from emerging threats as they arise. The extension is fully compatible with Firefox and integrates seamlessly with email services like Gmail and Outlook. Whether you're using Windows, macOS, or Linux, this extension adds an extra layer of security by safeguarding your email and browsing activities.

For the website, we used a Gemini model to provide a detailed analysis on why the URL given may or may not be a phishing link.

## Challenges we ran into
...
We were unable to utilize Gemini API to its fullest extent due to the API key expiring after each use of it on the website.  Scanning for links properly also proved to be a challenge due to the way the HTML is set up on certain websites such as Amazon, so we narrowed our scope to just Outlook and Gmail.

## Accomplishments that we're proud of
...
We are proud of the fact that we were able to turn this idea into a reality as quick and efficiently as we did.  We had multiple different versions this floating around in our heads for a bit, but this is the best concept that we had as a whole.  

## What we learned
...
We leanrned how to make extensions, train a model, and how to formulaicly determine the common callsigns of phishing links.

## What's next for Phising Extension (change name if needed)
...
Going forward we would like to have a larger database of both phishing links and confirmed safe sites.  Pitt could provide a more thorough list of these due to them throwing up the alarm on the phishing links and having a more extensive whitelist of Pitt-affiliated sites
