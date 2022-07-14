#!/usr/bin/env python3.10
# -*- coding: utf-8 -*-

from ownline_core import service, logger, config_name, config
import sys


if __name__ == '__main__':
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            logger.info("Starting ownline-core")
            logger.info(f"CONFIG NAME = {config_name}")
            if config_name == 'development':
                # If debugging not create a daemon, just run the service
                logger.info("non-daemon mode")
                service.run()
            elif config_name == 'production':
                logger.info(f"""
    PID_FILE = {config.PID_FILE}
    LOG_FILE = {config.LOG_FILE}""")
                logger.info("Daemon mode")
                service.start()
        elif 'stop' == sys.argv[1]:
            logger.warning("Stopping ownline-core")
            service.stop()
        elif 'restart' == sys.argv[1]:
            logger.warning("Restarting ownline-core")
            service.restart()
        else:
            logger.error("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        logger.warning("usage: {} start|stop|restart".format(sys.argv[0]))
        sys.exit(2)
