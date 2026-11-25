"""Authorization and operation dispatch, independent of the BLE transport."""
from __future__ import annotations

import sys

from .network import NetworkError, NetworkManager, safe_error
from .protocol import ProtocolError, REJECTED
from .state import StateError


class ProvisioningService:
    def __init__(self, session, state, backend=None):
        self.session, self.state = session, state
        self.backend = NetworkManager() if backend is None else backend

    async def handle(self, message, emit):
        try:
            if message.get("type") == "challenge_request":
                await emit(self.session.challenge(message))
                return
            request = self.session.authenticate(message)
        except (ProtocolError, ValueError):
            await emit(REJECTED)
            return

        async def event(value):
            await emit(request.reply(value))

        command = request.command
        try:
            if not request.valid:
                raise NetworkError("invalid_request")
            op = command["op"]
            if op == "echo":
                await event({"event": "echo", "final": True, "echo": command["text"]})
                return
            state = self.state.read()
            if op == "status":
                network = None if sys.platform != "linux" else await self.backend.status()
                await event({"event": "status", "final": True, "provisioned": state["provisioned"],
                             "setup_allowed": self.state.allowed(state), "network": network})
                return
            if not self.state.allowed(state):
                raise NetworkError("setup_closed")
            if op == "scan":
                await event({"event": "scanning", "final": False})
                result = await self.backend.scan()
                await event({"event": "networks", "final": True, **result})
                return

            async def progress(name):
                await event({"event": name, "final": False, "ssid": command["ssid"]})

            result = await self.backend.configure(command, progress)
            try:
                self.state.provisioned(result)
            except (OSError, StateError, ValueError) as exc:
                # Network transaction has committed. Never roll back a working network
                # because the separate local provisioning record could not be written.
                raise NetworkError("state_write_failed") from exc
            await event({"event": "connected", "final": True, "provisioned": True, **result})
        except Exception as exc:
            # Transport failures should propagate rather than attempting a second terminal
            # frame. For operational failures, only fixed safe messages cross this boundary.
            if request._final:
                raise
            await event(safe_error(exc).event())
        finally:
            command.pop("password", None)
