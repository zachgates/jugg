import asyncio
import re

from . import constants


def reactive_event_loop(loop, start_task, stop_task, run_forever = False):
    try:
        loop.run_until_complete(start_task)
        if run_forever:
            loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for task in asyncio.Task.all_tasks():
            task.cancel()

        loop.run_until_complete(stop_task)
        loop.stop()
        loop.close()


def validate_name(name):
    return bool(re.fullmatch(constants.NAME_REGEX, name))


__all__ = [
    reactive_event_loop,
    validate_name,
]
