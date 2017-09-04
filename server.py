import asyncio
import pyarchy
import socket
import srp
import ssl

from . import constants, settings, utils
from .core import ClientBase, Datagram
from .security import KeyHandler


class ClientAI(ClientBase):

    def __init__(self, stream_in, stream_out):
        ClientBase.__init__(self, stream_in, stream_out)

        self._commands[constants.CMD_LOGIN] = self.handle_login

    async def handle_login(self, dg : Datagram):
        # Initial login request
        if not utils.validate_name(dg.data):
            await self.send_error(constants.ERR_CREDENTIALS)
            return

        if not isinstance(dg.data, str) or \
           not self.verify_HMAC(
               dg.hmac.encode(),
               dg.data.encode(),
               settings.HMAC_KEY):
            await self.send_error(constants.ERR_HMAC)
            return
        else:
            await self.send_response(True)

        # Challenge
        response = await self.recv()

        if response and response.data:
            svr = srp.Verifier(
                self.name.encode('latin-1'),
                *srp.create_salted_verification_key(
                    self.name.encode(),
                    settings.CHALLENGE_PASSWORD),
                bytes.fromhex(response.data))
        else:
            return

        s, B = svr.get_challenge()
        if (s is None) or (B is None):
            await self.send_error(constants.ERR_CHALLENGE)
            return
        else:
            await self.send_response([s.hex(), B.hex()])

        # Verification
        response = await self.recv()

        if response and response.data:
            HAMK = svr.verify_session(bytes.fromhex(response.data))
            if HAMK and svr.authenticated():
                self.name = dg.data
                self.id = pyarchy.core.Identity()
                await self.send_response(HAMK.hex())
            else:
                await self.send_error(constants.ERR_VERIFICATION)


class Server(object):

    def __init__(self, host : str = None, port : int = None):
        KeyHandler.__init__(self)

        if host is None:
            self._host = settings.HOST
        else:
            self._host = host

        if port is None:
            self._port = settings.PORT
        else:
            self._port = port

        self._socket = None
        self._loop = None
        self._server = None

    async def new_connection(self, stream_in, stream_out):
        try:
            # Create the client on the server
            client = ClientAI(stream_in, stream_out)
            self.clients.add(client)
            # Maintain the connection
            await client.start()
            # Connection broke; remove the client from the server
            self.clients.remove(client)
        except asyncio.CancelledError:
            return

    def start(self):
        # Make the socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if settings.WANT_SSL and settings.CRT_FILE and settings.KEY_FILE:
            self._socket = ssl.wrap_socket(
                self._socket,
                keyfile = settings.KEY_FILE,
                certfile = settings.CRT_FILE,
                server_side = True,
                ssl_version = ssl.PROTOCOL_TLSv1_2,
                do_handshake_on_connect = True,
                ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384')

        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._host, self._port))

        # Establish the conncetion
        loop = asyncio.get_event_loop()
        self._server = loop.create_server(
            # Stream factory
            lambda: asyncio.StreamReaderProtocol(
                asyncio.StreamReader(loop = loop),
                self.new_connection,
                loop),
            sock = self._socket)

        # Make the client pool
        self.clients = pyarchy.data.ItemPool()
        self.clients.object_type = ClientBase

        # Maintain the connection
        utils.interactive_event_loop(
            loop,
            self._server,
            self.stop(),
            True)

    async def stop(self):
        # Cleanup
        pass


__all__ = [
    ClientAI,
    Server,
]


if __name__ == '__main__':
    server = Server()
    server.start()
