import asyncio
import json
import ssl
from daemons.prefab import run
from threading import current_thread
import logging

from ownline_core.core.ownline_action import OwnlineAction
from ownline_core.spa_server import OwnlineSPAServer
from ownline_core.utils.http import do_request_to_ownline_web_api


class OwnlineCoreService(run.RunDaemon):
    """
    OwnlineService daemon run method that starts a UDP server for incoming SPA packets and a TCP server to incoming ownline CMD messages
    """

    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        current_thread().setName("main-thread")
        self.logger = logging.getLogger("ownline_core_log")
        self.config = config
        # UDP SPA server
        self.spa_server = None
        # TCP SSL server for communicate with ownline-web
        self.cmd_server = None
        self.ownline_action = OwnlineAction(self.config)

    @asyncio.coroutine
    async def handle_cmd_connection(self, reader, writer):
        data = await reader.read(2048)
        message = data.decode()
        addr = writer.get_extra_info('peername')
        self.logger.info(f"Received cmd from {addr!r}: {message!r}")
        response = self.ownline_action.do_action(message)
        self.logger.info(f"Answer to ownline-web with: {response!r}")
        response_dumped = json.dumps(response, indent=None, separators=(',', ':'))
        writer.write(response_dumped.encode('utf-8'))
        await writer.drain()
        self.logger.info("Close the connection")
        writer.close()

    def run(self):
        self.logger.debug('Run method started')
        loop = asyncio.get_event_loop()

        # SPA server
        self.spa_server = loop.create_datagram_endpoint(
            lambda: OwnlineSPAServer(self.config),
            local_addr=('0.0.0.0', self.config.SPA_SERVER_BIND_PORT))
        loop.run_until_complete(self.spa_server)
        self.logger.info(f"SPA server created listening on: {('0.0.0.0', self.config.SPA_SERVER_BIND_PORT)}")

        # CMD Server
        sc = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sc.load_cert_chain(self.config.CMD_SERVER_CERT_PATH, self.config.CMD_SERVER_KEY_PATH,
                           password=self.config.CMD_SERVER_CERT_PASSWORD)
        # todo: check valid certificate? improve security?
        self.cmd_server = asyncio.start_server(self.handle_cmd_connection, self.config.CMD_SERVER_BIND_ADDRESS,
                                               self.config.CMD_SERVER_BIND_PORT, ssl=sc)
        loop.run_until_complete(self.cmd_server)
        self.logger.info(
            f"CMD server created listening on: {(self.config.CMD_SERVER_BIND_ADDRESS, self.config.CMD_SERVER_BIND_PORT)}")

        # Notify ownline-web that we need to reinitialize
        task = loop.create_task(do_request_to_ownline_web_api({"action": "ini"},
                                                              self.config.OWNLINE_WEB_SPA_ENDPOINT_AUTH_TOKEN,
                                                              self.config.OWNLINE_WEB_CORE_INI_ENDPOINT))
        self.logger.info(f"Notifying ownline-web that core needs to reinitialize... {task}")

        # MAIN INFINITE LOOP
        self.logger.info('Starting infinite loop')
        loop.run_forever()

        # Close the servers
        self.spa_server.close()
        loop.run_until_complete(self.spa_server.wait_closed())
        self.cmd_server.close()
        loop.run_until_complete(self.cmd_server.wait_closed())

        # Close the loop
        loop.close()
        self.logger.error('Loop finished??')
        self.logger.info("Exiting main loop without good initialization")

    def shutdown(self, signum):
        self.logger.info(f"Shutdown signal received with signum: {signum}")
        self.logger.info("Stopping loop")
        loop = asyncio.get_event_loop()
        loop.stop()
        super().shutdown(signum)
