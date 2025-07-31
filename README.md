# CrowdStrike Falcon Exclusion Manager

A Python script for managing sensor visibility exclusions across multiple child CIDs in CrowdStrike Falcon Flight Control environments.

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
- Parent CID with Flight Control (MSSP) access to child CIDs

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

## API Permissions Required

Your CrowdStrike API key needs the following scopes:
- **Flight Control**: Read and Write access for child CID management
- **Sensor Visibility Exclusions**: Write access for creating exclusions

## Logging

The script creates a log file `crowdstrike_exclusion_manager.log` in the current directory with detailed operation logs including:
- Authentication attempts
- Child CID retrieval operations
- Exclusion creation attempts
- API responses and errors

## Rate Limiting

The script implements automatic rate limiting:
- Waits 60 seconds after every 30 operations
- Small delays between operations to prevent API throttling
- Configurable rate limits in the `rate_limit_delay()` function

## Security Considerations

- Never hardcode API credentials in the script
- Use environment variables or secure credential management
- API credentials are prompted securely using `getpass`
- All operations are logged for audit purposes

## Exclusion Format

Sensor visibility exclusions support various formats:
- File paths: `/path/to/file`
- Process names: `process.exe`
- Registry keys: `HKEY_LOCAL_MACHINE\\Software\\...`

Refer to CrowdStrike documentation for complete exclusion format specifications.

## Error Handling

The script includes comprehensive error handling:
- Authentication failures
- Network connectivity issues
- API rate limiting
- Invalid CID access
- Malformed exclusion data

Failed operations are logged and reported in the summary.

## Example Output

```
CrowdStrike Falcon Exclusion Manager
========================================
Enter CrowdStrike API Client ID: your-client-id
Enter CrowdStrike API Client Secret: 
✓ Successfully authenticated with CrowdStrike Falcon

Retrieving child CIDs with filter: prod...
Found 3 matching child CIDs out of 10 total

Selected Child CIDs (3):
  - Production Environment (12345678-1234-1234-1234-123456789012)
  - Production-West (87654321-4321-4321-4321-210987654321)
  - Production-East (11111111-2222-3333-4444-555555555555)

Proceed to add exclusion to 3 CID(s)? (y/n): y

Applying exclusion: /opt/myapp/temp/*
==================================================
Processing Production Environment...
✓ Successfully added exclusion to Production Environment
  Exclusion ID: abc123def456

==================================================
SUMMARY REPORT
==================================================
Total CIDs processed: 3
Successful: 3
Failed: 0

Exclusion Details:
  Value: /opt/myapp/temp/*
  Comment: Temporary files exclusion for MyApp

✓ Successfully modified CIDs:
  - Production Environment (12345678-1234-1234-1234-123456789012)
    Exclusion ID: abc123def456
```