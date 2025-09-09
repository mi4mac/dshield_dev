import requests
import json
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('dshield')


class DShield:
    def __init__(self, config):
        self.base_url = config.get('server_url').strip('/') + '/api'
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.headers = {'content-type': 'application/json'}
        self.error_msg = {
            400: 'Bad/Invalid Request',
            401: 'Invalid credentials were provided',
            403: 'Access Denied',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'
        }

    def make_rest_call(self, endpoint, params=None, headers=None, data=None, method='GET'):
        url = '{0}{1}'.format(self.base_url, endpoint)
        logger.info('Request URL {}'.format(url))
        try:
            response = requests.request(method,
                                        url,
                                        json=data,
                                        headers=headers,
                                        params=params)
            if response.ok:
                return json.loads(response.content.decode('utf-8'))
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(self.error_msg['time_out']))
        except Exception as e:
            logger.exception('{}'.format(e))
            raise ConnectorError('{}'.format(e))


def _check_health(config):
    try:
        lookup_ip(config, {'ip': '8.8.8.8'})
    except Exception as err:
        raise ConnectorError('Invalid URL')


def lookup_ip(config, params):
    dshield_obj = DShield(config)
    endpoint = '/ip/{}?json'.format(params.get('ip'))
    return dshield_obj.make_rest_call(endpoint)


def get_threat_feeds(config, params):
    dshield_obj = DShield(config)
    endpoint = '/threatfeeds/?json'
    return dshield_obj.make_rest_call(endpoint)

operations = {
    'lookup_ip': lookup_ip,
    'get_threat_feeds': get_threat_feeds
}
