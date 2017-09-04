import asyncio
import base64
import pyarchy
import socket
import srp
import ssl

from . import constants, settings, utils
from .constants import ERROR_INFO_MAP
from .core import ClientBase, Datagram


class Client(ClientBase):

    def __init__(self, host : str = None, port : int = None):
        if host is None:
            self._host = settings.HOST
        else:
            self._host = host

        if port is None:
            self._port = settings.PORT
        else:
            self._port = port

        self._socket = None
        self._loop = asyncio.get_event_loop()

        streams = self._loop.run_until_complete(self.make_streams())
        ClientBase.__init__(self, *streams)

    async def make_streams(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if settings.WANT_SSL and settings.CRT_FILE:
            self._socket = ssl.wrap_socket(
                self._socket,
                ca_certs = settings.CRT_FILE,
                cert_reqs = ssl.CERT_REQUIRED,
                ssl_version = ssl.PROTOCOL_TLSv1_2,
                ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384')

        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.connect((self._host, self._port))

        return await asyncio.open_connection(
            loop = self._loop,
            sock = self._socket)

    async def send_login(self, name):
        # Intital login request
        hmac = self.generate_HMAC(name.encode(), settings.HMAC_KEY)
        await self.send(
            Datagram(
                command = constants.CMD_LOGIN,
                sender = self.id,
                recipient = self.id,
                data = name,
                hmac = base64.b85encode(hmac).decode()))
        response = await self.recv()

        if not response or response.data is not True:
            self.do_error(constants.ERR_CREDENTIALS)
            return

        # Challenge
        user = srp.User(name.encode(), settings.CHALLENGE_PASSWORD)
        username, auth = user.start_authentication()

        await self.send_response(auth.hex())
        response = await self.recv()

        if response and response.data:
            s, B = map(bytes.fromhex, response.data)
            M = user.process_challenge(s, B)

            if M is None:
                self.do_error(constants.ERR_CHALLENGE)
                return
            else:
                await self.send_response(M.hex())

        # Verification
        response = await self.recv()

        if response and response.data:
            HAMK = bytes.fromhex(response.data)
            user.verify_session(HAMK)

            if user.authenticated():
                self.name = name
                self.id = pyarchy.core.Identity(response.recipient)
        else:
            self.do_error(constants.ERR_VERIFICATION)

    async def send_hello(self, member_names):
        await self.send(
            Datagram(
                command = constants.CMD_HELLO,
                sender = self.id,
                recipient = self.id,
                data = member_names))


__all__ = [
    Client,
]
