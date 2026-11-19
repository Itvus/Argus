"""Platform compatibility helpers and Windows asyncio bug workarounds."""

import asyncio
import sys
from typing import Any, Coroutine, Optional


def apply_windows_asyncio_patches() -> None:
    """Fix Windows-specific CPython asyncio bugs.

    Prevents ConnectionResetError [WinError 10054] inside
    _ProactorBasePipeTransport._call_connection_lost when a remote HTTP host
    forcibly resets or closes a TCP socket during shutdown.
    """
    if sys.platform != "win32":
        return

    try:
        import asyncio.proactor_events

        target_cls = getattr(asyncio.proactor_events, "_ProactorBasePipeTransport", None)
        if target_cls and hasattr(target_cls, "_call_connection_lost"):
            orig_call_connection_lost = target_cls._call_connection_lost

            if not getattr(orig_call_connection_lost, "_is_argus_patched", False):

                def _safe_call_connection_lost(self, exc=None):
                    try:
                        orig_call_connection_lost(self, exc)
                    except (ConnectionResetError, ConnectionAbortedError, OSError) as err:
                        # Silently swallow WSAECONNRESET (10054), WSAECONNABORTED (10053), WSAENOTSOCK (10038)
                        winerror = getattr(err, "winerror", None)
                        if winerror in (10054, 10053, 10038) or isinstance(
                            err, (ConnectionResetError, ConnectionAbortedError)
                        ):
                            if hasattr(self, "_sock") and self._sock:
                                try:
                                    self._sock.close()
                                except Exception:
                                    pass
                                self._sock = None
                            self._called_connection_lost = True
                        else:
                            raise

                _safe_call_connection_lost._is_argus_patched = True
                target_cls._call_connection_lost = _safe_call_connection_lost
    except Exception:
        pass


def configure_loop_exception_handler(loop: asyncio.AbstractEventLoop) -> None:
    """Configure loop exception handler to suppress Windows winsock reset noise."""
    orig_handler = loop.get_exception_handler()

    def handler(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        msg = str(context.get("message") or "")
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
            return
        if getattr(exc, "winerror", None) in (10054, 10053, 10038):
            return
        if "_call_connection_lost" in msg or "10054" in msg:
            return
        if orig_handler:
            orig_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


def run_async(coro: Coroutine[Any, Any, Any]) -> Any:
    """Safely execute an async coroutine on Windows or POSIX without leaking socket reset noise."""
    if sys.platform == "win32":
        apply_windows_asyncio_patches()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if sys.platform == "win32":
        configure_loop_exception_handler(loop)

    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        finally:
            loop.close()
            asyncio.set_event_loop(None)


# Apply patch immediately upon module import
apply_windows_asyncio_patches()
