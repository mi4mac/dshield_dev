from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('dshield_dev')


class DShieldConnector(Connector):
    def execute(self, config, operation, operation_params, **kwargs):
        try:
            logger.info('DShieldConnector.execute called with operation: {}'.format(operation))
            logger.info('Config keys: {}'.format(list(config.keys()) if config else 'None'))
            logger.info('Operation params: {}'.format(operation_params))
            
            operation_func = operations.get(operation)
            if not operation_func:
                error_msg = 'Operation "{}" not found. Available operations: {}'.format(operation, list(operations.keys()))
                logger.error(error_msg)
                raise ConnectorError(error_msg)
            
            logger.info('Executing operation: {}'.format(operation))
            result = operation_func(config, operation_params)
            logger.info('Operation completed successfully')
            return result
            
        except ConnectorError as e:
            logger.error('ConnectorError in execute: {}'.format(str(e)))
            raise
        except Exception as err:
            logger.error('Unexpected error in execute: {}'.format(str(err)))
            logger.error('Error type: {}'.format(type(err).__name__))
            import traceback
            logger.error('Traceback: {}'.format(traceback.format_exc()))
            raise ConnectorError('Unexpected error in connector: {}'.format(str(err)))

    def check_health(self, config):
        try:
            logger.info('DShieldConnector.check_health called')
            result = _check_health(config)
            logger.info('Health check completed successfully')
            return result
        except Exception as e:
            logger.error('Health check failed: {}'.format(str(e)))
            raise ConnectorError('Health check failed: {}'.format(str(e)))

