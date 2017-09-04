import asyncio
import re

from . import settings


def interactive_event_loop(loop, start, stop, run_forever):
    try:
        loop.run_until_complete(start)
        if run_forever:
            loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for task in asyncio.Task.all_tasks():
            task.cancel()

        loop.run_until_complete(stop)
        loop.stop()
        loop.close()


def validate_name(name):
    return bool(re.fullmatch(settings.NAME_REGEX, name))


__all__ = [
    interactive_event_loop,
    validate_name,
]
