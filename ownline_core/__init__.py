import logging
import os
from .service import OwnlineCoreService
from ownline_core.config import configuration

# Loads configuration by environment
config_name = os.environ.get('OWNLINE_CORE_CONFIG_NAME') or 'development'

config = configuration[config_name]

logger = logging.getLogger("ownline_core_log")

if config_name == 'production':
    logging.basicConfig(filename=config.LOG_FILE, level=config.LOGGING_LEVEL, format='%(levelname)-5s - %(asctime)s - %(threadName)-13s - %(module)s : %(message)s')
else:
    logging.basicConfig(level=config.LOGGING_LEVEL, format='%(levelname)-5s - %(asctime)s - %(threadName)-13s - %(module)s : %(message)s')

logger.info("\n==============================================================================================================================================================================")

service = OwnlineCoreService(config=config, pidfile=config.PID_FILE)
