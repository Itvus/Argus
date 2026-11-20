"""Unit tests for avatar image EXIF and technical metadata inspection."""

import io
from unittest.mock import AsyncMock, patch
from PIL import Image
import pytest

from argus.modules.metadata_exif import inspect_avatar_metadata


@pytest.mark.asyncio
async def test_inspect_avatar_metadata():
    """Verify technical metadata (dimensions, format, mode) extraction on images."""
    # Create sample in-memory PNG
    buf = io.BytesIO()
    img = Image.new("RGBA", (128, 128), color=(255, 0, 0, 255))
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    async def mock_get(url, *args, **kwargs):
        resp = AsyncMock()
        resp.status_code = 200
        resp.content = png_bytes
        return resp

    with patch("httpx.AsyncClient.get", new=mock_get):
        reports, status = await inspect_avatar_metadata(
            [("Discord", "https://cdn.discordapp.com/avatars/123/abc.png")],
            timeout=5,
        )
        assert status.status == "success"
        assert len(reports) == 1
        rep = reports[0]
        assert rep.platform == "Discord"
        assert rep.format == "PNG"
        assert rep.dimensions == "128x128"
        assert rep.color_mode == "RGBA"
        assert rep.file_size_bytes == len(png_bytes)
