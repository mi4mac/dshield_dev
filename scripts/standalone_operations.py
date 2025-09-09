#!/usr/bin/env python3
"""
Standalone DShield Operations
Independent version of operations that doesn't require FortiSOAR connectors module
"""

import requests
import json
import re
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('dshield_dev')


class DShieldError(Exception):
    """Custom exception for DShield operations"""
    pass


class DShield:
    def __init__(self, config):
        server_url = config.get('server_url', '').strip()
        if not server_url:
            raise DShieldError('Server URL is required')
        
        # Clean up URL and ensure proper format
        if not server_url.startswith(('http://', 'https://')):
            server_url = 'https://' + server_url
        
        # Remove trailing slashes and add /api if not present
        server_url = server_url.rstrip('/')
        if not server_url.endswith('/api'):
            server_url = server_url + '/api'
            
        self.base_url = server_url
        
        # Get API key from config
        api_key = config.get('api_key', '').strip()
        if not api_key:
            raise DShieldError('API key is required for DShield authentication')
        
        # Set up headers with API key authentication
        self.headers = {
            'content-type': 'application/json', 
            'User-Agent': 'dshield_dev-Standalone/1.1.0',
            'Authorization': 'API_KEY {}'.format(api_key)
        }
        self.timeout = config.get('timeout', 30)
        self.error_msg = {
            400: 'Bad/Invalid Request - Check your parameters',
            401: 'Invalid credentials were provided',
            403: 'Access Denied - Insufficient permissions',
            404: 'Resource not found',
            429: 'Rate limit exceeded - Too many requests',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed',
            'connection_error': 'Failed to connect to the server',
            'invalid_response': 'Invalid response received from server'
        }

    def make_rest_call(self, endpoint, params=None, headers=None, data=None, method='GET'):
        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.info('Making {} request to: {}'.format(method, url))
        
        # Merge headers
        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            response = requests.request(
                method=method,
                url=url,
                json=data,
                headers=request_headers,
                params=params,
                timeout=self.timeout,
                verify=True
            )
            
            logger.info('Response status: {}'.format(response.status_code))
            
            if response.ok:
                # Check if response has content
                if not response.text.strip():
                    logger.warning('Empty response received from server')
                    return {'error': 'Empty response received from server', 'raw_response': ''}
                
                try:
                    return response.json()
                except json.JSONDecodeError as e:
                    logger.warning('Non-JSON response received: {}'.format(response.text[:200]))
                    logger.warning('JSON decode error: {}'.format(str(e)))
                    return {'raw_response': response.text}
            else:
                error_msg = self.error_msg.get(response.status_code, 'Unknown error occurred')
                logger.error('API Error {}: {}'.format(response.status_code, error_msg))
                raise DShieldError('API Error {}: {}'.format(response.status_code, error_msg))
                
        except requests.exceptions.Timeout:
            logger.exception('Request timeout')
            raise DShieldError(self.error_msg['time_out'])
        except requests.exceptions.ConnectionError as e:
            logger.exception('Connection error: {}'.format(e))
            raise DShieldError(self.error_msg['connection_error'])
        except requests.exceptions.SSLError as e:
            logger.exception('SSL error: {}'.format(e))
            raise DShieldError(self.error_msg['ssl_error'])
        except requests.exceptions.RequestException as e:
            logger.exception('Request error: {}'.format(e))
            raise DShieldError('Request failed: {}'.format(str(e)))
        except Exception as e:
            logger.exception('Unexpected error: {}'.format(e))
            raise DShieldError('Unexpected error: {}'.format(str(e)))


def _validate_ip_address(ip):
    """Validate IP address format"""
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(ip_pattern, ip) is not None


def _check_health(config):
    """Check the health of the DShield connector"""
    try:
        dshield_obj = DShield(config)
        # Try to access a simple endpoint to verify connectivity
        endpoint = '/threatfeeds/?json'
        response = dshield_obj.make_rest_call(endpoint)
        logger.info('Health check successful')
        return True
    except DShieldError as e:
        logger.error('Health check failed: {}'.format(str(e)))
        raise DShieldError('Health check failed: {}'.format(str(e)))
    except Exception as e:
        logger.error('Health check failed with unexpected error: {}'.format(str(e)))
        raise DShieldError('Health check failed: Unable to connect to DShield API')


def lookup_ip(config, params):
    """Lookup IP address information from DShield"""
    ip = params.get('ip', '').strip()
    
    if not ip:
        raise DShieldError('IP address parameter is required')
    
    if not _validate_ip_address(ip):
        raise DShieldError('Invalid IP address format: {}'.format(ip))
    
    try:
        dshield_obj = DShield(config)
        endpoint = '/ip/{}?json'.format(ip)
        logger.info('Looking up IP: {}'.format(ip))
        
        result = dshield_obj.make_rest_call(endpoint)
        
        # Add metadata to the response
        if isinstance(result, dict):
            result['_metadata'] = {
                'query_ip': ip,
                'source': 'DShield',
                'connector_version': '1.1.0'
            }
        
        return result
        
    except DShieldError:
        raise
    except Exception as e:
        logger.error('Error in lookup_ip: {}'.format(str(e)))
        raise DShieldError('Failed to lookup IP: {}'.format(str(e)))


def get_threat_feeds(config, params):
    """Get available threat feeds from DShield"""
    try:
        dshield_obj = DShield(config)
        endpoint = '/threatfeeds/?json'
        logger.info('Retrieving threat feeds from DShield')
        
        result = dshield_obj.make_rest_call(endpoint)
        
        # Add metadata to the response
        if isinstance(result, list):
            return {
                'threat_feeds': result,
                '_metadata': {
                    'source': 'DShield',
                    'connector_version': '1.1.0',
                    'total_feeds': len(result) if isinstance(result, list) else 0
                }
            }
        elif isinstance(result, dict):
            result['_metadata'] = {
                'source': 'DShield',
                'connector_version': '1.1.0'
            }
        
        return result
        
    except DShieldError:
        raise
    except Exception as e:
        logger.error('Error in get_threat_feeds: {}'.format(str(e)))
        raise DShieldError('Failed to retrieve threat feeds: {}'.format(str(e)))


def get_top_ports(config, params):
    """Get top ports information from DShield"""
    try:
        dshield_obj = DShield(config)
        endpoint = '/topports/?json'
        logger.info('Retrieving top ports from DShield')
        
        result = dshield_obj.make_rest_call(endpoint)
        
        # Add metadata to the response
        if isinstance(result, dict):
            result['_metadata'] = {
                'source': 'DShield',
                'connector_version': '1.1.0'
            }
        
        return result
        
    except DShieldError:
        raise
    except Exception as e:
        logger.error('Error in get_top_ports: {}'.format(str(e)))
        raise DShieldError('Failed to retrieve top ports: {}'.format(str(e)))


def get_daily_summary(config, params):
    """Get daily summary from DShield"""
    try:
        dshield_obj = DShield(config)
        # Use the working dailysummary endpoint instead of the broken /daily/?json endpoint
        # Get data for the last 7 days
        from datetime import datetime, timedelta
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        
        endpoint = '/dailysummary/{}/{}'.format(start_date, end_date)
        logger.info('Retrieving daily summary from DShield for period: {} to {}'.format(start_date, end_date))
        
        result = dshield_obj.make_rest_call(endpoint)
        
        # Handle case where endpoint returns empty response
        if isinstance(result, dict) and 'error' in result and 'Empty response' in result['error']:
            logger.warning('Daily summary endpoint returned empty response')
            return {
                'error': 'Daily summary endpoint returned empty response - endpoint may be broken',
                'raw_response': '',
                '_metadata': {
                    'source': 'DShield',
                    'connector_version': '1.1.0',
                    'note': 'This endpoint appears to be broken or deprecated'
                }
            }
        
        # Handle case where endpoint returns XML instead of JSON
        if isinstance(result, dict) and 'raw_response' in result:
            logger.info('Daily summary endpoint returned XML data')
            # Parse the XML response to extract useful information
            xml_content = result['raw_response']
            return {
                'daily_summary': xml_content,
                'summary_type': 'XML',
                'date_range': '{} to {}'.format(start_date, end_date),
                '_metadata': {
                    'source': 'DShield',
                    'connector_version': '1.1.0',
                    'endpoint': 'dailysummary',
                    'note': 'Returns XML format daily summary data'
                }
            }
        
        # Add metadata to the response
        if isinstance(result, dict):
            result['_metadata'] = {
                'source': 'DShield',
                'connector_version': '1.1.0',
                'endpoint': 'dailysummary'
            }
        
        return result
        
    except DShieldError:
        raise
    except Exception as e:
        logger.error('Error in get_daily_summary: {}'.format(str(e)))
        raise DShieldError('Failed to retrieve daily summary: {}'.format(str(e)))


def get_top_attacking_ips(config, params):
    """Get top attacking IPs from DShield"""
    try:
        dshield_obj = DShield(config)
        endpoint = '/topips/?json'
        logger.info('Retrieving top attacking IPs from DShield')
        
        result = dshield_obj.make_rest_call(endpoint)
        
        # Add metadata to the response
        if isinstance(result, dict):
            result['_metadata'] = {
                'source': 'DShield',
                'connector_version': '1.1.0'
            }
        
        return result
        
    except DShieldError:
        raise
    except Exception as e:
        logger.error('Error in get_top_attacking_ips: {}'.format(str(e)))
        raise DShieldError('Failed to retrieve top attacking IPs: {}'.format(str(e)))


operations = {
    'lookup_ip': lookup_ip,
    'get_threat_feeds': get_threat_feeds,
    'get_top_ports': get_top_ports,
    'get_daily_summary': get_daily_summary,
    'get_top_attacking_ips': get_top_attacking_ips
}
