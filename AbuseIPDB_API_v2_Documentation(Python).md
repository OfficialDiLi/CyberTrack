# AbuseIPDB API v2 Documentation (Python Focus)

## Introduction
The AbuseIPDB API allows programmatic access to its database of reported abusive IP addresses. The most common use case is integration with security tools like Fail2Ban. You need an API key, obtainable from your [AbuseIPDB account dashboard](https://www.abuseipdb.com/account).

## Core Endpoints

### 1. Check Endpoint (GET)
Query details for a single IP address.

**Purpose:** Retrieve reputation data, geolocation, ISP, and report history for an IP.

**Python Example:**
```python
import requests
import json

# Define endpoint and parameters
url = 'https://api.abuseipdb.com/api/v2/check'
querystring = {
    'ipAddress': '118.25.6.39',  # The IP to check
    'maxAgeInDays': '90'         # Optional: Only show reports from last 90 days (default: 30)
}

# Set headers (API key in header is recommended)
headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'    # Replace with your actual API key
}

# Make the request
response = requests.request(method='GET', url=url, headers=headers, params=querystring)

# Parse and format the response
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**Response Structure (Key Fields):**
```json
{
  "data": {
    "ipAddress": "118.25.6.39",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 100,  // **CRITICAL**: Score 0-100, >75% is highly abusive
    "countryCode": "CN",
    "countryName": "China",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
    "domain": "tencent.com",
    "hostnames": [],
    "isTor": false,
    "totalReports": 1,
    "numDistinctUsers": 1,
    "lastReportedAt": "2018-12-20T20:55:14+00:00",
    "reports": [ // Only included if 'verbose' parameter is used
      {
        "reportedAt": "2018-12-20T20:55:14+00:00",
        "comment": "Dec 20 20:55:14 srv206 sshd[13937]: Invalid user oracle from 118.25.6.39",
        "categories": [18, 22],
        "reporterId": 1,
        "reporterCountryCode": "US"
      }
    ]
  }
}
```

**Parameters:**
| Parameter | Required | Default | Min | Max | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ipAddress` | Yes | - | - | - | Valid IPv4 or IPv6 address. URL-encode for IPv6. |
| `maxAgeInDays` | No | 30 | 1 | 365 | Limits report history. |
| `verbose` | No | - | - | - | Include full report details. Omit for lighter payloads. |

---

### 2. Reports Endpoint (GET)
Fetch a paginated list of reports for a specific IP.

**Purpose:** See the detailed history of who reported the IP and why.

**Python Example:**
```python
import requests
import json

url = 'https://api.abuseipdb.com/api/v2/reports'
querystring = {
    'ipAddress': '176.111.173.242',
    'maxAgeInDays': '30',  # Optional
    'page': '1',           # Pagination
    'perPage': '25'        # Pagination (Max: 100)
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**Response Structure (Key Fields):**
```json
{
  "data": {
    "total": 2840,          // Total number of reports for this IP
    "page": 5,              // Current page number
    "count": 25,            // Number of reports on this page
    "perPage": 25,          // Items per page
    "lastPage": 114,        // Total number of pages
    "nextPageUrl": "...",   // URL for next page
    "previousPageUrl": "...", // URL for previous page
    "results": [
      {
        "reportedAt": "2022-05-01T21:00:03+00:00",
        "comment": "Invalid user joseph from 176.111.173.242 port 53860",
        "categories": [18, 22],
        "reporterId": 43121,
        "reporterCountryCode": "DE"
      }
    ]
  }
}
```

**Parameters:**
| Parameter | Required | Default | Min | Max | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ipAddress` | Yes | - | - | - | Valid IPv4 or IPv6 address. |
| `maxAgeInDays` | No | 30 | 1 | 365 | Filters reports by age. |
| `page` | No | 1 | 1 | - | Pagination control. |
| `perPage` | No | 25 | 1 | 100 | Number of results per page. |

---

### 3. Blacklist Endpoint (GET)
Retrieve a list of the most abusive IPs based on community reports.

**Purpose:** Get a dynamic, pre-calculated list of top offenders.

**Python Example (JSON):**
```python
import requests
import json

url = 'https://api.abuseipdb.com/api/v2/blacklist'
querystring = {
    'confidenceMinimum': '90'  // Only include IPs with 90%+ confidence
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**Python Example (Plaintext - for firewalls):**
```python
import requests

url = 'https://api.abuseipdb.com/api/v2/blacklist'
querystring = {
    'confidenceMinimum': '90',
    'plaintext': ''  // This flag triggers plain text output
}

headers = {
    'Accept': 'text/plain',  // OR use 'Accept: application/json' for JSON
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)
print(response.text)  // Output will be a simple list: 192.168.1.1\n192.168.1.2\n...
```

**Response Structure (JSON):**
```json
{
  "meta": {
    "generatedAt": "2020-09-24T19:54:11+00:00"
  },
  "data": [
    {
      "ipAddress": "5.188.10.179",
      "abuseConfidenceScore": 100,
      "lastReportedAt": "2020-09-24T19:17:02+00:00"
    },
    {
      "ipAddress": "185.222.209.14",
      "abuseConfidenceScore": 100,
      "lastReportedAt": "2020-09-24T19:17:02+00:00"
    }
  ]
}
```

**Parameters:**
| Parameter | Required | Default | Min | Max | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `confidenceMinimum` | No | 100 | 25 | 100 | **Crucial**: Use 75-100 for blocking. 25% is a minimum threshold to prevent false positives. |
| `limit` | No | 10,000 | 1 | See below | Max IPs returned depends on your subscription (Standard: 10k, Basic: 100k, Premium: 500k). |
| `plaintext` | No | - | - | - | Returns a newline-separated list of IPs. |
| `onlyCountries` | No | - | - | - | Filter by ISO 3166-1 alpha-2 codes (e.g., `US,MX,CA`). *Subscriber feature*. |
| `exceptCountries` | No | - | - | - | Exclude IPs from specific countries. *Subscriber feature*. |
| `ipVersion` | No | 4,6 mixed | - | - | Filter by IP version (`4` or `6`). |

**Subscription Limits for `limit` Parameter:**
| Subscription Tier | Max `limit` |
| :--- | :--- |
| Standard | 10,000 |
| Basic | 100,000 |
| Premium | 500,000 |

---

### 4. Report Endpoint (POST)
Submit a report for an abusive IP.

**Purpose:** Contribute to the community database by reporting observed attacks.

**Python Example:**
```python
import requests
import json

url = 'https://api.abuseipdb.com/api/v2/report'

# Define parameters as form data
params = {
    'ip': '180.126.219.126',           # The abusive IP
    'categories': '18,20',             # Comma-separated category IDs (see below)
    'comment': 'SSH brute force attack detected from this IP.',  # Detailed log snippet
    'timestamp': '2023-10-18T11:25:11-04:00'  # Optional: ISO 8601 time of attack
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='POST', url=url, headers=headers, data=params)
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**Response Structure:**
```json
{
  "data": {
    "ipAddress": "180.126.219.126",
    "abuseConfidenceScore": 52  // The updated score after your report
  }
}
```

**Category Reference (Common IDs):**
*   **18**: SSH Brute Force
*   **22**: FTP Brute Force
*   **20**: Web Application Attack
*   **14**: RDP Brute Force
*   **11**: DNS Query Abuse
*   *(See the full list on the AbuseIPDB website)*

**Parameters:**
| Parameter | Required | Notes |
| :--- | :--- | :--- |
| `ip` | Yes | Valid IPv4 or IPv6 address. |
| `categories` | Yes | Comma-separated list of category IDs. At least one required. |
| `comment` | No | A descriptive text of the attack (e.g., server logs). |
| `timestamp` | No | ISO 8601 datetime of the attack. Defaults to current time. |

---

### 5. Check-Block Endpoint (GET)
Check the reputation of an entire IP subnet (CIDR block).

**Purpose:** Assess the security posture of a network range.

**Python Example:**
```python
import requests
import json

url = 'https://api.abuseipdb.com/api/v2/check-block'
querystring = {
    'network': '192.168.1.0/24',  // CIDR notation
    'maxAgeInDays': '15'
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**Response Structure (Key Fields):**
```json
{
  "data": {
    "networkAddress": "192.168.1.0",
    "netmask": "255.255.255.0",
    "minAddress": "192.168.1.1",
    "maxAddress": "192.168.1.254",
    "numPossibleHosts": 254,
    "addressSpaceDesc": "Private",
    "reportedAddress": [
      {
        "ipAddress": "192.168.1.1",
        "numReports": 631,
        "mostRecentReport": "2019-03-21T16:35:16+00:00",
        "abuseConfidenceScore": 0,
        "countryCode": null
      },
      {
        "ipAddress": "192.168.1.2",
        "numReports": 16,
        "mostRecentReport": "2019-03-12T20:31:17+00:00",
        "abuseConfidenceScore": 0,
        "countryCode": null
      }
    ]
  }
}
```

**Parameters & Limits:**
| Parameter | Required | Default | Min | Max | **Subscription Limits** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `network` | Yes | - | - | - | Standard: `/24`, Basic: `/20`, Premium: `/16` |
| `maxAgeInDays` | No | 30 | 1 | 365 | Standard: 30, Basic: 60, Premium: 365 |

**Note:** Exceeding your subscription's limit will return a `402 Payment Required` error.

---

### 6. Bulk-Report Endpoint (POST)
Report multiple IPs from a CSV file in one request.

**Purpose:** Efficiently report a large list of IPs from your logs.

**Python Example:**
```python
import requests

url = 'https://api.abuseipdb.com/api/v2/bulk-report'

files = {
    'csv': ('report.csv', open('report.csv', 'rb'))  # Your CSV file
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='POST', url=url, headers=headers, files=files)
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**CSV Format:** One IP address per line.
**Response:**
```json
{
  "data": {
    "savedReports": 60,
    "invalidReports": [
      {
        "error": "Duplicate IP",
        "input": "41.188.138.68",
        "rowNumber": 5
      },
      {
        "error": "Invalid IP",
        "input": "127.0.foo.bar",
        "rowNumber": 6
      }
    ]
  }
}
```

---

### 7. Clear-Address Endpoint (DELETE)
Delete all reports made by your account for a specific IP.

**Purpose:** Remove a report you made in error.

**Python Example:**
```python
import requests
import json

url = 'https://api.abuseipdb.com/api/v2/clear-address'
querystring = {
    'ipAddress': '118.25.6.39'
}

headers = {
    'Accept': 'application/json',
    'Key': 'YOUR_OWN_API_KEY'
}

response = requests.request(method='DELETE', url=url, headers=headers, params=querystring)
decodedResponse = json.loads(response.text)
print(json.dumps(decodedResponse, sort_keys=True, indent=4))
```

**Response:**
```json
{
  "data": {
    "numReportsDeleted": 0
  }
}
```

---

## API Rate Limits (Daily)

| Endpoint | Standard | Webmaster | Supporter | Basic | Premium |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `check` | 1,000 | 3,000 | 5,000 | 10,000 | 50,000 |
| `reports` | 100 | 500 | 1,000 | 5,000 | 25,000 |
| `blacklist` | 5 | 10 | 20 | 100 | 500 |
| `report` | 1,000 | 3,000 | 1,000 | 10,000 | 50,000 |
| `check-block` | 100 | 250 | 500 | 1,000 | 5,000 |
| `bulk-report` | 5 | 10 | 20 | 100 | 500 |
| `clear-address` | 5 | 10 | 20 | 100 | 500 |

**Response Headers on Rate Limit (429):**
*   `Retry-After`: Seconds to wait before retrying.
*   `X-RateLimit-Limit`: Your daily limit.
*   `X-RateLimit-Remaining`: Requests left today.
*   `X-RateLimit-Reset`: Epoch timestamp when the limit resets.

**Always use `Accept: application/json`** to get structured error responses instead of HTML pages.

---

## Security & Best Practices

*   **HTTPS Only:** All requests must use `https://`.
*   **API Key Security:** **Always pass your API key in the HTTP header (`Key: YOUR_KEY`)**, not as a query parameter. Query parameters can be logged in server logs.
*   **CORS:** The API does not support Cross-Origin Resource Sharing. Do not use your API key in client-side JavaScript.
*   **Never Share Your Key:** AbuseIPDB support will never ask for your API key or password.
*   **Use `abuseConfidenceScore`:** Rely on this score (0-100) for automated actions, not `isWhitelisted`, which is a conservative flag.

---

## Testing

*   **Test IP:** Reporting `127.0.0.2` will trigger a `429 Too Many Requests` error after 15 minutes, useful for testing rate limiting.


