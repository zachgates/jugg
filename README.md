# imposter
A secure, end-to-end encrypted communication framework

## Example
Below is a basic example of a client-server connection. No commands are executed and no login takes place, but the handshake is performed, as it is implicit.

Server:
```python
import imposter

sv = imposter.server.Server('127.0.0.1', 1500)
sv.start()
```

Client:
```python
import asyncio
import imposter

cl = imposter.client.Client('127.0.0.1', 1500)

imposter.utils.reactive_event_loop(
    asyncio.get_event_loop(),
    cl.start(), cl.stop(),
    run_forever = False)
```
