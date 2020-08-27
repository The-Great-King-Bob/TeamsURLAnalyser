// installations needed:

// apt install nodejs
// apt install npm
// npm install --save request
// npm install --save request-promise
// npm install --save whois
// npm install --save dotenv

// -----------------------------------

require('dotenv').config();
const request = require('request-promise');
const crypto = require('crypto');
const sharedSecret = process.env.TEAMS_SHARED_SECRET; //teams webhook shared secret
const bufSecret = Buffer(sharedSecret, "base64");
const http = require('http');
const PORT = process.env.port || process.env.PORT || 8080; //Listening port

//function to conduct a whois lookup on a given URL
//output is limited to first eight (8) lines, for more increase while loop count from 8
function getWhois() {
	var datasplit;
	return new Promise(function(resolve, reject) {
		var whois = require('whois');
		whois.lookup(url, function(err, data1) {
			if (err) {
				console.log(err);
			}
			var i = 0;
			var whoisResult = '';
			while (i < 8) {
				var datasplit = data1.split('\n')[i];
				var whoisResult = whoisResult + datasplit + '   \n';
				i++;
			}
			resolve(whoisResult);
		})
	})
}

function getVT(){
	return new Promise((resolve, reject) =>{
		var options = {
			url: 'https://www.virustotal.com/vtapi/v2/url/report?apikey=' + process.env.VT_API_KEY + '&resource=' + url
		};
		request(options)
			.then(function(response) {
				var obj =JSON.parse(response)
				try {
					VTurl = JSON.stringify(obj.resource, null, 2);
					VTlink = JSON.stringify(obj.permalink, null, 2);
					VTdate = JSON.stringify(obj.scan_date, null, 2);
					VTresults = JSON.stringify(obj.positives, null, 2);
					VTtotal = JSON.stringify(obj.total, null, 2);
					VTscan = '   \n   \nURL: ' + VTurl + '   \nLink: ' + VTlink + '   \nScan Date: ' + VTdate + '   \nResults: ' + VTresults + '/' + VTtotal + '\n\n'
				} catch (error) {
					VTscan = 'VT Error: ' + error;
				}
				resolve(VTscan);
			})
			.catch(function(err) {
				VTscan = 'Error: ' + err;
				reject(VTscan);
			})
	})
}

//Function to collect IBM xForce data from the API.
function getxForce() {
	return new Promise((resolve, reject) => {
		var options = {
			url: 'https://api.xForce.ibmcloud.com/url/' + url + '',
			auth: {
				'user': process.env.XFORCE_USER_API_KEY,
				'pass': process.env.XFORCE_PASSWORD_API_KEY
			}
		};

		request(options)
			.then(function(response) {
				var obj = JSON.parse(response)
				xUrl = JSON.stringify(obj.result.url, null, 2);
				xCats = JSON.stringify(obj.result.cats, null, 2);
				xScore = JSON.stringify(obj.result.score, null, 2);
				try {
					xDescription = JSON.stringify(obj.result.application.description, null, 2);
				} catch (error) {
					xDescription = ''
				}
				try {
					xRisk = JSON.stringify(obj.result.application.riskfactors, null, 2);
				} catch (error) {
					xRisk = ''
				}
				try {
					xScore = JSON.stringify(obj.result.application.score, null, 2);
				} catch (error) {
				}
				obj = 'URL: ' + xUrl + '   \n   \n Categories: ' + xCats + '   \n   \n Score: ' + xScore + '   \n   \n Description: ' + xDescription + '   \n   \n Risk Factors: ' + xRisk + '   \n   \n ';
				resolve(obj);
				})
				.catch(function(err) {
					console.log('error:', err);
					obj = 'Error: No IBM xForce Data Found'
					resolve(obj);
				})
	})
}

function getQuad9(){
        return new Promise((resolve, reject) =>{
		var options = {
		url: 'https://api.quad9.net/search/' + url + '?callback=jQuery32105243281257028427_1597999249965&_=1597999249966',
		headers: header
		};
		var header = {
			'Connection': 'keep-alive',
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36',
			'DNT': '1',
			'Accept': '*/*',
			'Sec-Fetch-Site': 'same-site',
			'Sec-Fetch-Mode': 'no-cors',
			'Sec-Fetch-Dest': 'script',
			'Referer': 'https://www.quad9.net/result/?url=' + url,
			'Accept-Language': 'en-US,en;q=0.9'
		};
                request(options)
                        .then(function(response) {
				obj = response.match(/(?<=\()(.*)(?=\))/igm)
                                var obj =JSON.parse(obj)
                                try {
                                        quad9Results = JSON.stringify(obj);
					quad9Results = quad9Results.replace(',', '   \n')
                                } catch (error) {
                                        quad9Results = 'Quad9 Error: ' + error;
                                }
                                resolve(quad9Results);
                        })
        })
}


//Due to the outbound webhook within teams only lasting 5 seconds,
//a inbound webhook is used to push the results back to teams.
function teamsMessagePush() {
	var headers = {
		'Content-Type': 'application/json'
	};
	try {
		lookupData = '**whois:**' + '   \n' + arguments[0] + '**Virus Total Results:**' + '   \n' + arguments[1] + '**IBM xForce:**' + '   \n' + arguments[2] + '\n**Quad9:**' + '   \n' + arguments[3];
	} catch (error) {
		lookupData = arguments[0];
	}
	//removes special characters from API results as this will result in the webhook failing
	lookupData = lookupData.replace(/[^a-zA-Z0-9:*.,_/s\-\r\n]/g, ' ');
	var dataString = '{"text": "' + lookupData + '"}';

	var options = {
		url: process.env.TEAMS_WEBHOOK_URL,
		method: 'POST',
		headers: headers,
		body: dataString
	};

	function callback(error, response, body) {
		if (!error && response.statusCode == 200) {
		}
	}
	request(options, callback);
}

http.createServer(function(request, response) {
	var payload = '';
	// Process the request
	request.on('data', function(data) {
		payload += data;
	});

	// Respond to the request
	request.on('end', async function() {
		try {
			// Retrieve authorization HMAC information
			var auth = this.headers['authorization'];
			// Calculate HMAC on the message we've received using the shared secret
			var msgBuf = Buffer.from(payload, 'utf8');
			var msgHash = "HMAC " + crypto.createHmac('sha256', bufSecret).update(msgBuf).digest("base64");
			// console.log("Computed HMAC: " + msgHash);
			// console.log("Received HMAC: " + auth);

			//function accepts request and sends response from/to MS Teams
			response.writeHead(200);
			if (msgHash === auth) {
				var receivedMsg = JSON.parse(payload);
				//remove sanitisation from URL
				url = receivedMsg.text.replace(/[^a-zA-Z0-9:*._ \/]/g, '');
				//regex to filter URL to domain and sub domains
				try {
					match = url.match(/(?:(?:https?|ftp|file)^:\/\/|[-A-Z0-9]{1,60}\.)(?:\([-A-Z0-9+&@#%=~_|$?!:,.]*\)|[-A-Z0-9+&@#%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#%=~_|$?!:,.]*\)|[A-Z0-9+&@#%=~_|$])/im);
					url = match[0]
					url = url.toString();
					//regex to filter out subdomains
					url = url.match(/([^.*]{0,256}(?:\.[^.]{2,20})?$)/igm)
					url = url.toString();
					url = url.replace('nbsp', '')
					url = url.replace(',', '')
					//calls API functions as an await (waits for function to resolve before continuing)
					var lookup = await getWhois();
					//checks if whois reply is valid
					//creates team reply with whois info
					if (lookup.match(/No match for domain/i) || lookup.match(/StatusCodeError: 404/i)) {
						var responseMsg = '{ "type": "message", "text": "No whois match found for domain" }';
						response.end(responseMsg);
					} else {
						var responseMsg = '{ "type": "message", "text": "URL lookup: ' + url + '" }';
						response.end(responseMsg);
						var VT = await getVT();
						var xForce = await getxForce();
						var quad9 = await getQuad9();
						teamsMessagePush(lookup, VT, xForce, quad9);
					}
				} catch (error) {
					console.log(error);
					var responseMsg = url + 'is not a valid URL'
					teamsMessagePush(responseMsg, NULL, NULL);
				}
			} else {
				//error if shared key is incorrect or message is not authenticated
				var responseMsg = '{ "type": "message", "text": "Error: message sender cannot be authenticated." }';
				response.end(responseMsg);
			}
		} catch (err) {
			response.writeHead(400);
			return response.end("Error: " + err + "\n" + err.stack);
		}
	});
}).listen(PORT);

console.log('Listening on port %s', PORT);

//error catcher for all unhandled promise rejects
//should never run, is only here for future proofing code
//Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code
process.on('unhandledRejection', function(err) {
	console.log(err);
});
