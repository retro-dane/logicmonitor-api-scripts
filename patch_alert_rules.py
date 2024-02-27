#!/bin/env python

import requests
import json
import hashlib
import base64
import time
import hmac
import csv

count = 0

# Proxies (if needed)
proxy = {}

# Account Info
AccessId = ''  # LogicMonitor Access ID
AccessKey = ''  # LogicMonitor Access Key
Company = ''  # LogicMonitor company name

## File Information
filename = "./AlertRulesToBePatched.csv"

# Open the CSV file containing alert rules data
with open(filename, encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    
    # Iterate over each row in the CSV file
    for row in reader:
        # Extract alert rule information from the row
        items = eval(row["items"])
        name = items["name"]
        id = items["id"]

        # Check if the rule name contains "Error" As script will just look to patch all Alert rules of type Error
        if "Error" not in name:
            print("Skipping rule '%s' as it does not contain 'Error'." % name)
        else:
            # Increment the count for each rule containing "Error"
            count += 1

            # Request Info
            httpVerb = 'PATCH'
            resourcePath = '/setting/alert/rules/%s' % (id)
            queryParams = ''
            data = '{"priority":%s}' % (count + 201)

            # Construct URL
            url = 'https://' + Company + '.logicmonitor.com/santaba/rest' + resourcePath

            # Get current time in milliseconds
            epoch = str(int(time.time() * 1000))

            # Concatenate Request details
            requestVars = httpVerb + epoch + data + resourcePath

            # Construct signature using HMAC-SHA256
            digest = hmac.new(
                AccessKey.encode('utf-8'),
                msg=requestVars.encode('utf-8'),
                digestmod=hashlib.sha256).hexdigest()
            signature = base64.b64encode(digest.encode('utf-8')).decode('utf-8')

            # Construct headers
            auth = 'LMv1 ' + AccessId + ':' + str(signature) + ':' + epoch
            headers = {'Content-Type': 'application/json', 'Authorization': auth, 'X-Version': '3'}

            # Make PATCH request to update priority of the rule
            response = requests.patch(url, data=data, headers=headers, proxies=proxy, verify=False)

            # Print status and body of response
            print('URL:', url)
            print('Response Status:', response.status_code)
            print('Response Body:', response.content)
