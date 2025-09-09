# dshield_dev FortiSOAR Connector

A FortiSOAR connector for DShield threat intelligence platform that provides investigative actions for IP lookups, threat feeds, and security intelligence.

## Features

- **IP Address Lookup**: Get detailed information about IP addresses including ASN, country, attack counts, and threat feed data
- **Threat Feeds**: Retrieve available threat feeds from DShield
- **Top Ports**: Get information about most attacked ports
- **Daily Summary**: Access daily attack summaries with XML parsing support
- **Top Attacking IPs**: Retrieve information about top attacking IP addresses
- **Shared Library Architecture**: Eliminates code duplication and improves maintainability
- **Standardized Error Handling**: Consistent exception handling across all operations
- **FortiSOAR Compliance**: Full compliance with FortiSOAR connector standards

## Operations

### Available Operations

1. **lookup_ip**: Lookup detailed information about an IP address
   - Parameters: `ip` (required) - IP address to lookup
   - Returns: IP information including ASN, country, attack counts, threat feeds

2. **get_threat_feeds**: Get available threat feeds from DShield
   - Parameters: None
   - Returns: List of available threat feeds with metadata

3. **get_top_ports**: Get top ports information
   - Parameters: None
   - Returns: Most attacked ports with counts and percentages

4. **get_daily_summary**: Get daily summary statistics
   - Parameters: None
   - Returns: Daily attack summaries for the last 7 days with XML parsing

5. **get_top_attacking_ips**: Get top attacking IP addresses
   - Parameters: None
   - Returns: Top attacking IPs with attack counts and geographic data

### Configuration

- **Server URL**: DShield server URL (default: https://www.dshield.org)
- **API Key**: DShield API key for authentication (optional for public endpoints)
- **Request Timeout**: Request timeout in seconds (default: 30)

## Installation

1. Copy the connector files to your FortiSOAR connectors directory
2. Install dependencies: `pip install -r requirements.txt`
3. Restart FortiSOAR services
4. Configure the connector with your DShield server URL (API key is optional)

## Architecture

### Shared Library (`dshield_lib.py`)
- Contains all core DShield API functionality
- Eliminates code duplication between connector and standalone scripts
- Provides standardized error handling with `DShieldError` exception
- Includes proper FortiSOAR-compliant authentication headers

### Connector Module (`operations.py`)
- Thin wrapper around shared library functions
- Converts `DShieldError` to `ConnectorError` for FortiSOAR compatibility
- Maintains backward compatibility with existing FortiSOAR integrations

### Standalone Scripts
- Located in `scripts/` directory
- Import from shared library to avoid duplication
- Provide command-line interface for all operations
- Support both JSON and table output formats

## Python Scripts

The connector includes Python scripts in the `scripts/` directory that provide standalone functionality:

- `dshield_dev_lookup_ip.py`: Standalone IP lookup script
- `dshield_dev_get_threat_feeds.py`: Standalone threat feeds script
- `dshield_dev_operations.py`: Combined operations script
- `standalone_operations.py`: Shared operations module for scripts

See the [scripts/README.md](scripts/README.md) for detailed usage instructions.

## API Endpoints

The connector uses the following DShield API endpoints:

- `/ip/{ip}?json` - IP address lookup
- `/threatfeeds/?json` - Available threat feeds
- `/topports/?json` - Top attacked ports
- `/dailysummary/{start_date}/{end_date}` - Daily summary (XML format)
- `/topips/?json` - Top attacking IPs

## Error Handling

- **Standardized Exceptions**: All operations use `DShieldError` internally, converted to `ConnectorError` for FortiSOAR
- **Comprehensive Error Messages**: Detailed error messages for different failure scenarios
- **Network Error Handling**: Proper handling of timeouts, SSL errors, and connection issues
- **API Error Mapping**: HTTP status codes mapped to meaningful error messages

## Version History

- **v1.1.0**: 
  - Added shared library architecture to eliminate code duplication
  - Standardized exception handling across all files
  - Improved FortiSOAR compliance with proper headers and metadata
  - Enhanced error handling and input validation
  - Added comprehensive output schemas in info.json
  - Removed empty test files
  - Updated documentation and README
  - Fixed authentication headers for FortiSOAR compliance
  - Added API key authentication support (optional)
  - Enhanced daily summary XML parsing
  - Added comprehensive logging

- **v1.0.0**: Initial release with basic IP lookup and threat feeds

## Support

For issues and support, please refer to the DShield documentation at https://www.dshield.org/help.html

## Compliance

This connector is fully compliant with:
- FortiSOAR connector standards (v7.0.0+)
- DShield API specifications
- FortiSOAR authentication requirements
- FortiSOAR output schema standards

