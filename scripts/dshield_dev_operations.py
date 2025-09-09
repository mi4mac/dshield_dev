#!/usr/bin/env python3
"""
DShield Operations Script
Combined script for all DShield operations
"""

import sys
import json
import argparse
from datetime import datetime

# Import standalone operations
from standalone_operations import (
    lookup_ip, get_threat_feeds, get_top_ports, 
    get_daily_summary, get_top_attacking_ips, DShieldError
)


def main():
    parser = argparse.ArgumentParser(description='DShield Operations Script')
    parser.add_argument('operation', choices=[
        'lookup_ip', 'get_threat_feeds', 'get_top_ports', 
        'get_daily_summary', 'get_top_attacking_ips'
    ], help='Operation to perform')
    
    parser.add_argument('--ip', help='IP address (for lookup_ip operation)')
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
    params = {}
    if args.ip:
        params['ip'] = args.ip
    
    try:
        print(f"Performing operation: {args.operation}")
        print(f"Server: {args.server_url}")
        print("-" * 50)
        
        # Perform the operation
        if args.operation == 'lookup_ip':
            if not args.ip:
                print("Error: --ip parameter is required for lookup_ip operation", file=sys.stderr)
                return 1
            result = lookup_ip(config, params)
        elif args.operation == 'get_threat_feeds':
            result = get_threat_feeds(config, params)
        elif args.operation == 'get_top_ports':
            result = get_top_ports(config, params)
        elif args.operation == 'get_daily_summary':
            result = get_daily_summary(config, params)
        elif args.operation == 'get_top_attacking_ips':
            result = get_top_attacking_ips(config, params)
        
        if args.output == 'json':
            output = json.dumps(result, indent=2)
        else:
            # Table format
            output = format_result_table(args.operation, result)
        
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


def format_result_table(operation, result):
    """Format result as a table based on operation type"""
    if not isinstance(result, dict):
        return str(result)
    
    lines = []
    lines.append(f"DShield {operation.replace('_', ' ').title()} Results")
    lines.append("=" * 50)
    
    # Metadata
    if '_metadata' in result:
        lines.append(f"Source: {result['_metadata'].get('source', 'N/A')}")
        lines.append(f"Connector Version: {result['_metadata'].get('connector_version', 'N/A')}")
        if 'query_ip' in result['_metadata']:
            lines.append(f"Query IP: {result['_metadata']['query_ip']}")
        if 'total_feeds' in result['_metadata']:
            lines.append(f"Total Feeds: {result['_metadata']['total_feeds']}")
        lines.append("")
    
    # Operation-specific formatting
    if operation == 'lookup_ip' and 'ip' in result:
        lines.extend(format_ip_info(result['ip']))
    elif operation == 'get_threat_feeds' and 'threat_feeds' in result:
        lines.extend(format_threat_feeds(result['threat_feeds']))
    elif operation == 'get_top_ports':
        lines.extend(format_top_ports(result))
    elif operation == 'get_daily_summary':
        lines.extend(format_daily_summary(result))
    elif operation == 'get_top_attacking_ips':
        lines.extend(format_top_attacking_ips(result))
    else:
        # Generic formatting
        for key, value in result.items():
            if key != '_metadata':
                lines.append(f"{key}: {value}")
    
    return '\n'.join(lines)


def format_ip_info(ip_info):
    """Format IP information"""
    lines = []
    lines.append("IP Information:")
    lines.append(f"  IP Address: {ip_info.get('number', 'N/A')}")
    lines.append(f"  Network: {ip_info.get('network', 'N/A')}")
    lines.append(f"  AS Number: {ip_info.get('as', 'N/A')}")
    lines.append(f"  AS Name: {ip_info.get('asname', 'N/A')}")
    lines.append(f"  AS Country: {ip_info.get('ascountry', 'N/A')}")
    lines.append(f"  Attack Count: {ip_info.get('count', 'N/A')}")
    lines.append(f"  Max Risk: {ip_info.get('maxrisk', 'N/A')}")
    return lines


def format_threat_feeds(feeds):
    """Format threat feeds"""
    lines = []
    lines.append("Available Threat Feeds:")
    if isinstance(feeds, list) and feeds:
        for i, feed in enumerate(feeds, 1):
            if isinstance(feed, dict):
                lines.append(f"  {i}. {feed.get('name', 'Unknown')}")
                lines.append(f"     Type: {feed.get('type', 'N/A')}")
                lines.append(f"     Frequency: {feed.get('frequency', 'N/A')}")
    else:
        lines.append("  No threat feeds available.")
    return lines


def format_top_ports(result):
    """Format top ports"""
    lines = []
    lines.append("Top Ports Information:")
    # Add specific formatting based on actual API response structure
    for key, value in result.items():
        if key != '_metadata':
            lines.append(f"  {key}: {value}")
    return lines


def format_daily_summary(result):
    """Format daily summary"""
    lines = []
    lines.append("Daily Summary:")
    for key, value in result.items():
        if key != '_metadata':
            lines.append(f"  {key}: {value}")
    return lines


def format_top_attacking_ips(result):
    """Format top attacking IPs"""
    lines = []
    lines.append("Top Attacking IPs:")
    for key, value in result.items():
        if key != '_metadata':
            lines.append(f"  {key}: {value}")
    return lines


if __name__ == '__main__':
    sys.exit(main())