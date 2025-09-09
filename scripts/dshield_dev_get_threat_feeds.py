#!/usr/bin/env python3
"""
DShield Threat Feeds Script
Replaces the playbook functionality for getting threat feeds
"""

import sys
import json
import argparse
from datetime import datetime

# Import standalone operations
from standalone_operations import get_threat_feeds, DShieldError


def main():
    parser = argparse.ArgumentParser(description='DShield Threat Feeds Script')
    parser.add_argument('--server-url', default='https://www.dshield.org', 
                       help='DShield server URL (default: https://www.dshield.org)')
    parser.add_argument('--timeout', type=int, default=30, 
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--output', choices=['json', 'table'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--save-to-file', help='Save results to file')
    parser.add_argument('--filter-type', help='Filter feeds by type')
    parser.add_argument('--filter-frequency', help='Filter feeds by frequency')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'server_url': args.server_url,
        'timeout': args.timeout
    }
    
    # Parameters
    params = {}
    
    try:
        print("Retrieving threat feeds from DShield...")
        print(f"Server: {args.server_url}")
        print("-" * 50)
        
        # Get threat feeds
        result = get_threat_feeds(config, params)
        
        # Apply filters if specified
        if args.filter_type or args.filter_frequency:
            result = apply_filters(result, args.filter_type, args.filter_frequency)
        
        if args.output == 'json':
            output = json.dumps(result, indent=2)
        else:
            # Table format
            output = format_threat_feeds_table(result)
        
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


def apply_filters(result, filter_type=None, filter_frequency=None):
    """Apply filters to threat feeds results"""
    if not isinstance(result, dict) or 'threat_feeds' not in result:
        return result
    
    feeds = result['threat_feeds']
    if not isinstance(feeds, list):
        return result
    
    filtered_feeds = []
    for feed in feeds:
        if not isinstance(feed, dict):
            continue
            
        # Apply type filter
        if filter_type and feed.get('type', '').lower() != filter_type.lower():
            continue
            
        # Apply frequency filter
        if filter_frequency and feed.get('frequency', '').lower() != filter_frequency.lower():
            continue
            
        filtered_feeds.append(feed)
    
    result['threat_feeds'] = filtered_feeds
    result['_metadata']['total_feeds'] = len(filtered_feeds)
    
    return result


def format_threat_feeds_table(result):
    """Format threat feeds result as a table"""
    if not isinstance(result, dict):
        return str(result)
    
    lines = []
    lines.append("DShield Threat Feeds")
    lines.append("=" * 50)
    
    # Metadata
    if '_metadata' in result:
        lines.append(f"Total Feeds: {result['_metadata'].get('total_feeds', 0)}")
        lines.append(f"Source: {result['_metadata'].get('source', 'N/A')}")
        lines.append(f"Connector Version: {result['_metadata'].get('connector_version', 'N/A')}")
        lines.append("")
    
    # Threat feeds
    if 'threat_feeds' in result and isinstance(result['threat_feeds'], list):
        feeds = result['threat_feeds']
        if feeds:
            lines.append("Available Threat Feeds:")
            lines.append("-" * 30)
            
            for i, feed in enumerate(feeds, 1):
                if isinstance(feed, dict):
                    lines.append(f"{i}. {feed.get('name', 'Unknown')}")
                    lines.append(f"   Description: {feed.get('description', 'N/A')}")
                    lines.append(f"   Type: {feed.get('type', 'N/A')}")
                    lines.append(f"   Data Type: {feed.get('datatype', 'N/A')}")
                    lines.append(f"   Frequency: {feed.get('frequency', 'N/A')}")
                    lines.append(f"   Last Update: {feed.get('lastupdate', 'N/A')}")
                    lines.append("")
        else:
            lines.append("No threat feeds available.")
    else:
        lines.append("No threat feeds data found.")
    
    return '\n'.join(lines)


if __name__ == '__main__':
    sys.exit(main())
