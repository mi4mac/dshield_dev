from connectors.core.connector import get_logger, ConnectorError
from .dshield_lib import (
    operations, _check_health, DShieldError
)

logger = get_logger('dshield_dev')


def _convert_dshield_error_to_connector_error(func):
    """Decorator to convert DShieldError to ConnectorError for FortiSOAR compatibility"""
    def wrapper(config, params):
        try:
            return func(config, params)
        except DShieldError as e:
            raise ConnectorError(str(e))
    return wrapper


# Wrap all operations to convert DShieldError to ConnectorError
lookup_ip = _convert_dshield_error_to_connector_error(operations['lookup_ip'])
get_threat_feeds = _convert_dshield_error_to_connector_error(operations['get_threat_feeds'])
get_top_ports = _convert_dshield_error_to_connector_error(operations['get_top_ports'])
get_daily_summary = _convert_dshield_error_to_connector_error(operations['get_daily_summary'])
get_top_attacking_ips = _convert_dshield_error_to_connector_error(operations['get_top_attacking_ips'])


# Export operations dictionary for connector.py
operations = {
    'lookup_ip': lookup_ip,
    'get_threat_feeds': get_threat_feeds,
    'get_top_ports': get_top_ports,
    'get_daily_summary': get_daily_summary,
    'get_top_attacking_ips': get_top_attacking_ips
}
