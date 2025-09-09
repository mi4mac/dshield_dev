#!/usr/bin/env python3
"""
DShield IP Lookup Script
Replaces the playbook functionality for IP lookup operations
"""

import sys
import json
import argparse
from datetime import datetime

# Import standalone operations
from standalone_operations import lookup_ip, DShieldError


def main():
    parser = argparse.ArgumentParser(description='DShield IP Lookup Script')
    parser.add_argument('--ip', required=True, help='IP address to lookup')
    parser.add_argument('--server-url', default='https://www.dshield.org', 
                       help='DShield server URL (default: https://www.dshield.org)')
    parser.add_argument('--timeout', type=int, default=30, 
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--output', choices=['json', 'table'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--save-to-file', help='Save results to file')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'server_url': args.server_url,
        'timeout': args.timeout
    }
    
    # Parameters
    params = {
        'ip': args.ip
    }
    
    try:
        print(f"Looking up IP: {args.ip}")
        print(f"Server: {args.server_url}")
        print("-" * 50)
        
        # Perform the lookup
        result = lookup_ip(config, params)
        
        if args.output == 'json':
            output = json.dumps(result, indent=2)
        else:
            # Table format
            output = format_ip_result_table(result)
        
        print(output)
        
        # Save to file if requested
        if args.save_to_file:
            with open(args.save_to_file, 'w') as f:
                f.write(output)
            print(f"\nResults saved to: {args.save_to_file}")
        
        return 0
        
    except DShieldError as e:
        print(f"DShield Error: {str(e)}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def format_ip_result_table(result):
    """Format IP lookup result as a table"""
    if not isinstance(result, dict):
        return str(result)
    
    lines = []
    lines.append("DShield IP Lookup Results")
    lines.append("=" * 50)
    
    # Basic IP information
    if 'ip' in result:
        ip_info = result['ip']
        lines.append(f"IP Address: {ip_info.get('number', 'N/A')}")
        lines.append(f"Network: {ip_info.get('network', 'N/A')}")
        lines.append(f"AS Number: {ip_info.get('as', 'N/A')}")
        lines.append(f"AS Name: {ip_info.get('asname', 'N/A')}")
        lines.append(f"AS Country: {ip_info.get('ascountry', 'N/A')}")
        lines.append(f"AS Size: {ip_info.get('assize', 'N/A')}")
        lines.append(f"Attack Count: {ip_info.get('count', 'N/A')}")
        lines.append(f"Max Risk: {ip_info.get('maxrisk', 'N/A')}")
        lines.append(f"First Seen: {ip_info.get('mindate', 'N/A')}")
        lines.append(f"Last Seen: {ip_info.get('maxdate', 'N/A')}")
        lines.append(f"Updated: {ip_info.get('updated', 'N/A')}")
        
        # Alexa information
        if 'alexa' in ip_info and ip_info['alexa']:
            alexa = ip_info['alexa']
            lines.append("\nAlexa Information:")
            lines.append(f"  Hostname: {alexa.get('hostname', 'N/A')}")
            lines.append(f"  Last Rank: {alexa.get('lastrank', 'N/A')}")
            lines.append(f"  First Seen: {alexa.get('firstseen', 'N/A')}")
            lines.append(f"  Last Seen: {alexa.get('lastseen', 'N/A')}")
            lines.append(f"  Domains: {alexa.get('domains', 'N/A')}")
        
        # Threat feeds
        if 'threatfeeds' in ip_info and ip_info['threatfeeds']:
            lines.append("\nThreat Feed Information:")
            for feed_name, feed_data in ip_info['threatfeeds'].items():
                if feed_data:
                    lines.append(f"  {feed_name.title()}:")
                    lines.append(f"    First Seen: {feed_data.get('firstseen', 'N/A')}")
                    lines.append(f"    Last Seen: {feed_data.get('lastseen', 'N/A')}")
    
    # Metadata
    if '_metadata' in result:
        lines.append(f"\nMetadata:")
        lines.append(f"  Source: {result['_metadata'].get('source', 'N/A')}")
        lines.append(f"  Connector Version: {result['_metadata'].get('connector_version', 'N/A')}")
        lines.append(f"  Query IP: {result['_metadata'].get('query_ip', 'N/A')}")
    
    return '\n'.join(lines)


if __name__ == '__main__':
    sys.exit(main())
