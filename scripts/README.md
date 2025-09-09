# dshield_dev Python Scripts

This directory contains Python scripts that provide standalone functionality for DShield operations. These scripts use the shared library architecture to eliminate code duplication and provide a more flexible and maintainable approach to interacting with the DShield API.

## Architecture

All scripts now use the shared library (`dshield_lib.py`) located in the parent directory, which provides:
- Standardized error handling with `DShieldError` exception
- Consistent API client implementation
- Proper FortiSOAR-compliant authentication headers
- Eliminated code duplication

## Available Scripts

### 1. `dshield_dev_lookup_ip.py`
Performs IP address lookups using the DShield API.

**Usage:**
```bash
python dshield_dev_lookup_ip.py --ip 8.8.8.8
python dshield_dev_lookup_ip.py --ip 8.8.8.8 --output table
python dshield_dev_lookup_ip.py --ip 8.8.8.8 --save-to-file results.json
```

**Options:**
- `--ip`: IP address to lookup (required)
- `--server-url`: DShield server URL (default: https://www.dshield.org)
- `--timeout`: Request timeout in seconds (default: 30)
- `--output`: Output format - json or table (default: json)
- `--save-to-file`: Save results to file

### 2. `dshield_dev_get_threat_feeds.py`
Retrieves available threat feeds from DShield.

**Usage:**
```bash
python dshield_dev_get_threat_feeds.py
python dshield_dev_get_threat_feeds.py --output table
python dshield_dev_get_threat_feeds.py --filter-type malware
```

**Options:**
- `--server-url`: DShield server URL (default: https://www.dshield.org)
- `--timeout`: Request timeout in seconds (default: 30)
- `--output`: Output format - json or table (default: json)
- `--save-to-file`: Save results to file
- `--filter-type`: Filter feeds by type
- `--filter-frequency`: Filter feeds by frequency

### 3. `dshield_dev_operations.py`
Combined script for all DShield operations.

**Usage:**
```bash
python dshield_dev_operations.py lookup_ip --ip 8.8.8.8
python dshield_dev_operations.py get_threat_feeds
python dshield_dev_operations.py get_top_ports
python dshield_dev_operations.py get_daily_summary
python dshield_dev_operations.py get_top_attacking_ips
```

**Operations:**
- `lookup_ip`: Lookup IP address information
- `get_threat_feeds`: Get available threat feeds
- `get_top_ports`: Get top ports information
- `get_daily_summary`: Get daily summary with XML parsing
- `get_top_attacking_ips`: Get top attacking IPs

**Options:**
- `--ip`: IP address (for lookup_ip operation)
- `--server-url`: DShield server URL (default: https://www.dshield.org)
- `--timeout`: Request timeout in seconds (default: 30)
- `--output`: Output format - json or table (default: json)
- `--save-to-file`: Save results to file

### 4. `standalone_operations.py`
Shared operations module that imports from the parent directory's `dshield_lib.py`. This module provides backward compatibility for scripts while eliminating code duplication.

## Features

- **Shared Library Architecture**: All scripts use the same core functionality from `dshield_lib.py`
- **Standardized Error Handling**: Consistent `DShieldError` exception handling across all scripts
- **Input Validation**: Validates IP addresses and other parameters
- **Multiple Output Formats**: JSON and table formats
- **Filtering**: Filter threat feeds by type and frequency
- **File Output**: Save results to files
- **Logging**: Detailed logging for debugging
- **Metadata**: Includes metadata in responses for tracking
- **FortiSOAR Compliance**: Proper authentication headers and error handling

## Dependencies

- Python 3.6+
- requests library
- Standard library modules (json, argparse, datetime, re, sys, xml.etree.ElementTree)

## Installation

1. Ensure Python 3.6+ is installed
2. Install required dependencies:
   ```bash
   pip install requests
   ```
3. Make scripts executable (optional):
   ```bash
   chmod +x *.py
   ```

## Examples

### Basic IP Lookup
```bash
python dshield_dev_lookup_ip.py --ip 8.8.8.8 --output table
```

### Get All Threat Feeds
```bash
python dshield_dev_get_threat_feeds.py --output table
```

### Get Daily Summary with XML Parsing
```bash
python dshield_dev_operations.py get_daily_summary --output table
```

### Save Results to File
```bash
python dshield_dev_operations.py lookup_ip --ip 8.8.8.8 --save-to-file ip_lookup.json
```

### Filter Threat Feeds
```bash
python dshield_dev_get_threat_feeds.py --filter-type malware --output table
```

## Error Handling

The scripts include comprehensive error handling for:
- Network connectivity issues
- Invalid IP addresses
- API errors (400, 401, 403, 404, 429, 500, 503)
- Timeout errors
- SSL certificate issues
- Invalid responses
- XML parsing errors (for daily summary)

## API Endpoints Used

- `/ip/{ip}?json` - IP address lookup
- `/threatfeeds/?json` - Available threat feeds
- `/topports/?json` - Top attacked ports
- `/dailysummary/{start_date}/{end_date}` - Daily summary (XML format)
- `/topips/?json` - Top attacking IPs

## Migration from Playbooks

These scripts replace the functionality previously provided by playbooks:
- `Get Threat Feeds` playbook → `dshield_dev_get_threat_feeds.py`
- `Lookup IP` playbook → `dshield_dev_lookup_ip.py`
- All operations → `dshield_dev_operations.py`

The scripts provide the same functionality with improved error handling, validation, and flexibility while using a shared library architecture to eliminate code duplication.
