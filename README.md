# CrowdStrike Falcon Exclusion Manager

A Python script for managing sensor visibility exclusions across multiple child CIDs in CrowdStrike Falcon Flight Control environments.

This script was made for a specific use, there is no support offered on GitHub for this repo. 

## Features

- **Multi-tenant Management**: Manages exclusions across multiple child CIDs under a parent account
- **Child CID Filtering**: Filter child CIDs by name for targeted operations
- **Interactive Interface**: Prompts for all required inputs including API credentials and exclusion details
- **Comprehensive Logging**: Detailed logging to file and console with timestamps
- **Rate Limiting**: Built-in API rate limiting to prevent API throttling
- **Error Handling**: Robust error handling with fallback mechanisms
- **Summary Reporting**: Detailed summary of successful and failed operations

## Prerequisites

- Python 3.7 or higher
- CrowdStrike Falcon API credentials with appropriate permissions

---

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd CrowdstrikePythonExclusion
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script:
```bash
python crowdstrike_exclusion_manager.py
```

The script will prompt you for:
- CrowdStrike API Client ID
- CrowdStrike API Client Secret
- Child CID name filter (optional)
- Exclusion value (path/process to exclude)
- Exclusion comment

## Logging

The script creates a log file `crowdstrike_exclusion_manager.log` in the current directory with detailed operation logs including:
- Authentication attempts
- Child CID retrieval operations
- Exclusion creation attempts
- API responses and errors

---

## Rate Limiting

The script implements automatic rate limiting:
- Waits 60 seconds after every 30 operations
- Small delays between operations to prevent API throttling
- Configurable rate limits in the `rate_limit_delay()` function

## Error Handling

The script includes comprehensive error handling:
- Authentication failures
- Network connectivity issues
- API rate limiting
- Invalid CID access
- Malformed exclusion data

Failed operations are logged and reported in the summary.
