#!/usr/bin/env python3
"""
Standalone DShield Operations
Independent version of operations that doesn't require FortiSOAR connectors module
"""

import sys
import os
import logging

# Add parent directory to path to import dshield_lib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import shared library
from dshield_lib import (
    operations, DShieldError, _check_health
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('dshield_dev')

# Export operations for backward compatibility
lookup_ip = operations['lookup_ip']
get_threat_feeds = operations['get_threat_feeds']
get_top_ports = operations['get_top_ports']
get_daily_summary = operations['get_daily_summary']
get_top_attacking_ips = operations['get_top_attacking_ips']
