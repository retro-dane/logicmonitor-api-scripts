#This Python script is designed to retrieve alert rules from a LogicMonitor account using the LogicMonitor REST API.
#It sends an authenticated GET request to the LogicMonitor API endpoint and saves the retrieved data to a CSV file. 
#Additionally, it prints the status code and body of the response for verification purposes.

#!/bin/env python

import requests
import json
import hashlib
import base64
import time
import hmac
import pandas as pd

# Proxies (if needed)
proxy = {
  
}

# Account Info
AccessId = ''  # LogicMonitor Access ID
AccessKey = ''  # LogicMonitor Access Key
Company = ''  # LogicMonitor company name

# Request Info
httpVerb = 'GET'
resourcePath = '/setting/alert/rules'
queryParams = '?sort=+name&fields=name,id&size=100'
data = ''

# Construct URL
url = 'https://' + Company + '.logicmonitor.com/santaba/rest' + resourcePath + queryParams

# Get current time in milliseconds
epoch = str(int(time.time() * 1000))

# Concatenate Request details
requestVars = httpVerb + epoch + data + resourcePath

# Construct signature
digest = hmac.new(
    AccessKey.encode('utf-8'),
    msg=requestVars.encode('utf-8'),
    digestmod=hashlib.sha256).hexdigest()
signature = base64.b64encode(digest.encode('utf-8')).decode('utf-8')

# Construct headers
auth = 'LMv1 ' + AccessId + ':' + str(signature) + ':' + epoch
headers = {'Content-Type': 'application/json', 'Authorization': auth, 'X-Version': '3'}

# Make request
response = requests.get(url, data=data, headers=headers, proxies=proxy, verify=False)
data = response.json()
devices = pd.DataFrame(data)

# Save data to CSV
devices.to_csv("./AllALertRules.csv")

# Print status and body of response
print('DATA', devices)
print('Response Status:', response.status_code)
print('Response Body:', data)
