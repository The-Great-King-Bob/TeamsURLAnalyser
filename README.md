# Teams URL Analyser

Teams URL Analyser is a script written in nodeJS that allows Teams webhooks to be used to pass a URL and APIs used to conduct analysis.
APIs currently implemented:
  - WHOIS lookup
  - Virus Total
  - IBM X-Force
  - Quad9 DNS block check

More APIs will be added in the future.

### Installation

Teams URL Analyser requires [Node.js](https://nodejs.org/) to run.

Install the dependencies listed.

```sh
$ apt update
$ apt install nodejs
$ apt install npm
$ npm install --save request
$ npm install --save request-promise
$ npm install --save whois
$ npm install --save dotenv
```

Rename the .env.example file to .env

```sh
$ mv .env.example .env
```

Create an outbound webhook within your Microsoft Teams application, with the URL of your server hosting Teams URL Analyser. Name this as the name you want to call  Completion of this will provide you with a shared secret. This should be inputted into your .env file as "TEAMS\_SHARED\_SECRET". 

Create a inbound webhook within your Microsoft Teams application. Completion of this will give you a URL. This should be inputted into your .env file as "TEAMS\_WEBHOOK\_URL"

If you wish to use Virus Total, your Virus Total API key should be inputted into your .env file as "VT\_API\_KEY"

If you wish to use IBM X-Force, your IBM X-Force API keys should be inputted into your .env file as "XFORCE\_USER\_API\_KEY" and "XFORCE\_PASSWORD\_API\_KEY"

**If API keys are not inputted, then those API lookups will be ignored**

Currently, this software uses ngrok (https://ngrok.com/) to provide a HTTPS secure tunnel for the interaction between Teams and Teams URL Analyser.

**If using a webserver setup to use HTTPS/TLS then ngrok is not needed. Script may need editing to run HTTPS.**

Install and setup ngrok using the ngrok documentation and start a https secure tunnel on port 8080 using the following command:

```sh
$ ./ngrok http 8080
```

A https tunnel should be established similar to:

```
https://7bfc7221822f.ngrok.io -> http://localhost:8080
```

Input this url into your outgoing webhook as the "callback URL".



Run the script using the following command:

```sh
$ nodejs TeamsURLAnalyser.js
```

Setup is now complete. 
Test Teams URL Analyser by calling the outbound webhook within teams followed by a URL as below:
```
@TUA www.google.com
```
```
whois:
Domain Name: google.com
Registry Domain ID: 2138514DOMAINCOM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2019-09-09T08:39:04-0700
Creation Date: 1997-09-15T00:00:00-0700
Registrar Registration Expiration Date: 2028-09-13T00:00:00-0700
Registrar: MarkMonitor, Inc.

Virus Total Results:   
URL:  google.com
Link:  https://www.virustotal.com/gui/url/cf4b367e49bf0b22041c6f065f4aa19f3cfe39c8d5abc0617343d1a66c6a26f5/detection/u-cf4b367e49bf0b22041c6f065f4aa19f3cfe39c8d5abc0617343d1a66c6a26f5-1598027554
Scan Date:  2020-08-21 16:32:34
Results: 0/78

IBM xForce:
URL:  google.com    
Categories:
   Search Engines / Web Catalogues / Portals : true
Score: 1   
Description:    
Risk Factors:    

Quad9:
 domain : google.com
 blocked :false
```
### Todos

 - Implement TLS within the script without relying on ngrok.
 - Add more API functions

License
----
MIT
