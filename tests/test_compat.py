"""Unit tests for Windows asyncio compatibility and socket reset error suppression."""

import asyncio
import sys
from argus.compat import (
    apply_windows_asyncio_patches,
    configure_loop_exception_handler,
    run_async,
)


def test_apply_windows_asyncio_patches():
    apply_windows_asyncio_patches()
    if sys.platform == "win32":
        import asyncio.proactor_events

        cls = getattr(asyncio.proactor_events, "_ProactorBasePipeTransport", None)
        assert cls is not None
        assert getattr(cls._call_connection_lost, "_is_argus_patched", False) is True


def test_configure_loop_exception_handler_suppresses_reset():
    loop = asyncio.new_event_loop()
    try:
        configure_loop_exception_handler(loop)

        # Simulate WinError 10054
        exc = ConnectionResetError("An existing connection was forcibly closed by the remote host")
        exc.winerror = 10054
        context = {
            "message": "Exception in callback _ProactorBasePipeTransport._call_connection_lost()",
            "exception": exc,
        }

        # Handler should silently drop this exception without re-raising or writing to stderr
        handler = loop.get_exception_handler()
        assert handler is not None
        handler(loop, context)
    finally:
        loop.close()


def test_run_async_executes_cleanly():
    async def sample_coro():
        await asyncio.sleep(0.01)
        return "success"

    result = run_async(sample_coro())
    assert result == "success"
