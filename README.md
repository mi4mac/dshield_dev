# dshield_dev FortiSOAR Connector

A FortiSOAR connector for DShield threat intelligence platform that provides investigative actions for IP lookups, threat feeds, and security intelligence.

## Features

- **IP Address Lookup**: Get detailed information about IP addresses including ASN, country, attack counts, and threat feed data
- **Threat Feeds**: Retrieve available threat feeds from DShield
- **Top Ports**: Get information about most attacked ports
- **Daily Summary**: Access daily attack summaries
- **Top Attacking IPs**: Retrieve information about top attacking IP addresses

## Operations

### Available Operations

1. **lookup_ip**: Lookup detailed information about an IP address
2. **get_threat_feeds**: Get available threat feeds from DShield
3. **get_top_ports**: Get top ports information
4. **get_daily_summary**: Get daily summary statistics
5. **get_top_attacking_ips**: Get top attacking IP addresses

### Configuration

- **Server URL**: DShield server URL (default: https://www.dshield.org)
- **API Key**: DShield API key for authentication (required)
- **Request Timeout**: Request timeout in seconds (default: 30)

## Installation

1. Copy the connector files to your FortiSOAR connectors directory
2. Install dependencies: `pip install -r requirements.txt`
3. Restart FortiSOAR services
4. Configure the connector with your DShield server URL and API key

## Python Scripts

The connector includes Python scripts in the `scripts/` directory that provide standalone functionality:

- `dshield_dev_lookup_ip.py`: Standalone IP lookup script
- `dshield_dev_get_threat_feeds.py`: Standalone threat feeds script
- `dshield_dev_operations.py`: Combined operations script

See the [scripts/README.md](scripts/README.md) for detailed usage instructions.

## Version History

- **v1.1.0**: Added API key authentication support, improved FortiSOAR compliance, added missing package files, enhanced error handling, input validation, additional operations, Python scripts
- **v1.0.0**: Initial release with basic IP lookup and threat feeds

## Support

For issues and support, please refer to the DShield documentation at https://www.dshield.org/help.html

