'''
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
# Using python, pandas and AWS SES create a script which obtains recent software vulnerabilities from the NVD and
# filters on specific products of interest.
# https://docs.aws.amazon.com/ses/latest/DeveloperGuide/quick-start.html
# To receive emails on specific products get a free AWS SES account linked to emails, create keys then update line 230 with email.
# To update emails for filtered and unfiltered products use lines  130ish and 170ish.
# Run this script in an EC2 instance using crond or as a Lambda Function on a set interval or trigger of your choice.

import pandas as pd
import numpy as np
import datetime
import time
from datetime import datetime
from datetime import timedelta
from pandas.io.json import json_normalize
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import ssl
import os
import sys
import io
import requests
import json
import smtplib

# NVD updates the zip files approximately every 2 hours.
# https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

ssl._create_default_https_context = ssl._create_unverified_context

proxies = {'http': 'http://example.proxy:1234',
           'https': 'https://example.proxy:1234'}
s = requests.get(
    'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip', proxies=proxies)

dfall = pd.read_json(io.BytesIO(s.content), compression='zip')

email_from = "email_from@example.com"
#to
email_to = "email_to@example.com"
#emailserver
email_server = "mail.example.com"
email_port = 25
use_ssl = False
email_login = "login"
email_password = "password"


# parse nested json


def flatten_json(nested_json: dict, exclude: list = [''], sep: str = '_') -> dict:
    out = dict()

    def flatten(x: (list, dict, str), name: str = '', exclude=exclude):
        if type(x) is dict:
            for a in x:
                if a not in exclude:
                    flatten(x[a], f'{name}{a}{sep}')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, f'{name}{i}{sep}')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(nested_json)
    return out


dfall = pd.DataFrame([flatten_json(x) for x in dfall['CVE_Items']])
dfall = dfall[['cve_CVE_data_meta_ID', 'publishedDate', 'lastModifiedDate', 'cve_description_description_data_0_value',
               'impact_baseMetricV3_cvssV3_baseScore',
               'impact_baseMetricV3_cvssV3_baseSeverity', 'impact_baseMetricV3_exploitabilityScore',
               'cve_references_reference_data_0_url']]

# date and time setup
dfall['date_time'] = pd.to_datetime(
    'today', utc=True, format="%Y-%m-%d %H:%M:%S")

# time calculation based on modification date
dfall['lastModifiedDate'] = pd.to_datetime(
    dfall['lastModifiedDate'], infer_datetime_format=False)
dfall['hours_since_lastmod'] = (
                                       dfall['lastModifiedDate'] - dfall['date_time']) / np.timedelta64(1, 'h')
# round down
dfall['hours_since_lastmod'] = dfall['hours_since_lastmod'].apply(np.floor)

# time calculation based on publication date
dfall['publishedDate'] = pd.to_datetime(
    dfall['publishedDate'], infer_datetime_format=False)
dfall['hours_since_pubdate'] = (
                                       dfall['publishedDate'] - dfall['date_time']) / np.timedelta64(1, 'h')
# round down
dfall['hours_since_pubdate'] = dfall['hours_since_pubdate'].apply(np.floor)

# time calculation based on modification dates and times. may need tweaking
dfall['lastModifiedDate'] = pd.to_datetime(
    dfall['lastModifiedDate'], infer_datetime_format=False)
dfall['days_since_lastmod'] = (
                                      dfall['lastModifiedDate'] - dfall['date_time']) / np.timedelta64(1, 'D')

# round down
dfall['days_since_lastmod'] = dfall['days_since_lastmod'].apply(np.floor)
dfall = dfall.sort_values(by='hours_since_lastmod', ascending=False)

# masks to create a boolean conditions for dataframe filtering on timeframes.
# hours
last1hourmods = dfall['hours_since_lastmod'] >= -1
last2hourmods = dfall['hours_since_lastmod'] >= -2
last2hoursnewpubs = dfall['hours_since_pubdate'] >= -2
last3hourmods = dfall['hours_since_lastmod'] >= -3
last4hourmods = dfall['hours_since_lastmod'] >= -4
last5hourmods = dfall['hours_since_lastmod'] >= -5

# days
lastdays = dfall['days_since_lastmod'] >= -2

# usage of masks created above
dfall = dfall[lastdays]

# URL concatenation. Bind URL: "https://nvd.nist.gov/vuln/detail/" + CVE-ID and make it available for use in the email.
cveids = dfall['cve_CVE_data_meta_ID']
burl = 'https://nvd.nist.gov/vuln/detail/'
cve_urls = [burl + x for x in cveids]
dfall['NVD_URL'] = cve_urls

html = dfall.to_html(justify='left', classes='table')

# filter so that we only see CVE's with a V3 CVSS score of 7.5 or greater and apply the AND mask for hourly check
cvsscore = dfall['impact_baseMetricV3_cvssV3_baseScore'] > 3.9
dfall = dfall[cvsscore]

# Filter products we want to INCLUDE and then send HTML output via email on the CVE's based on set conditions.
search_values = ['Chrome', 'Firefox', 'Windows',
                 'Linux', 'Kibana', 'nginx']
dfall = dfall[dfall.cve_description_description_data_0_value.str.contains(
    '|'.join(search_values))]

# sort results before output
dfall = dfall.sort_values(by='publishedDate', ascending=False)
# dfall.to_csv(r'Product_Vulnerabilities.csv')
# Rename in order to: | Published Date | CVE ID | Product Description | Severity | Exploitability Score | URL
dfall = dfall.rename(
    columns={"cve_CVE_data_meta_ID": "CVE ID",
             "publishedDate": "Date Published",
             "lastModifiedDate": "Date Modified",
             "cve_description_description_data_0_value": "Product",
             "impact_baseMetricV3_cvssV3_baseScore": "CVSS Score",
             "impact_baseMetricV3_cvssV3_baseSeverity": "Severity",
             "impact_baseMetricV3_exploitabilityScore": "Exploit Score",
             "NVD_URL": "NVD URL",
             "cve_references_reference_data_0_url": "URL for Detailed Information", })

outprods = dfall[['CVE ID', 'Date Published', 'Date Modified', 'Product', 'CVSS Score',
                  'Severity', 'Exploit Score', 'NVD URL', 'URL for Detailed Information']]

# output a csv file for troubleshooting when required.
# outprods.to_csv(r'Product_Vulnerabilities.csv')

rowcount = outprods.shape[0]
outpods2 = outprods.to_json(orient='index', date_format='iso')
if rowcount == 0:
    print('No new vulnerable products')
    sys.exit(0)
else:
    for item, value in json.loads(outpods2).items():
        email_text = 'CVE ID: ' + value['CVE ID']  + '\nDate Published: ' + value['Date Published']  + '\nDate Modified: ' \
                    + value['Date Modified']  + '\nProduct: ' + value['Product']  + '\nCVSS Score: ' + str(value['CVSS Score']) \
                    + '\nSeverity: ' + value['Severity']  + '\nExploit Score: ' + str(value['Exploit Score'])  + '\nNVD URL: ' \
                    + value['NVD URL']  + '\nURL for Detailed Information: ' + value['URL for Detailed Information']
        msg = MIMEText(email_text)
        msg['From'] = email_from
        msg['To'] = email_to
        msg['Subject'] = value['CVE ID']
        s = smtplib.SMTP(email_server,email_port)
        if use_ssl:
            s.starttls()
        s.login(email_login, email_password)
        s.sendmail(email_from,[email_to], msg.as_string())
        s.quit()
        print(value['CVE ID'] + " sended!")
