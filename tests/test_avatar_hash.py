"""Unit tests for avatar perceptual difference hashing (dHash) and matching."""

import io
import pytest
import unittest.mock
from PIL import Image, ImageDraw

from argus.modules.avatar_hash import (
    compute_dhash,
    hamming_distance,
    fetch_and_hash_avatars,
)


def create_test_image_bytes(color: tuple, add_shape: bool = False, format: str = "PNG") -> bytes:
    img = Image.new("RGB", (64, 64), color=color)
    if add_shape:
        draw = ImageDraw.Draw(img)
        draw.rectangle([10, 10, 40, 40], fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()


def test_compute_dhash_and_hamming_distance():
    raw1 = create_test_image_bytes((200, 50, 50), add_shape=True, format="PNG")
    # Identical content saved as compressed JPEG
    raw2 = create_test_image_bytes((200, 50, 50), add_shape=True, format="JPEG")
    # Completely different image
    raw3 = create_test_image_bytes((10, 200, 10), add_shape=False, format="PNG")

    h1 = compute_dhash(raw1)
    h2 = compute_dhash(raw2)
    h3 = compute_dhash(raw3)

    assert h1 is not None
    assert h2 is not None
    assert h3 is not None

    # Identical image compressed to JPEG should have distance 0 or 1
    dist_same = hamming_distance(h1, h2)
    assert dist_same <= 2

    # Different image should have high distance (> 10)
    dist_diff = hamming_distance(h1, h3)
    assert dist_diff > 10


@pytest.mark.asyncio
async def test_fetch_and_hash_avatars_matching():
    img_a = create_test_image_bytes((100, 150, 200), add_shape=True, format="PNG")
    img_b = create_test_image_bytes((100, 150, 200), add_shape=True, format="JPEG")

    async def fake_get(url, **kwargs):
        resp = unittest.mock.MagicMock()
        resp.status_code = 200
        if "discord" in url:
            resp.content = img_a
        elif "steam" in url:
            resp.content = img_b
        return resp

    mock_client = unittest.mock.AsyncMock()
    mock_client.get.side_effect = fake_get
    mock_client.__aenter__.return_value = mock_client

    sources = [
        ("Discord", "https://cdn.discordapp.com/avatars/123/abc.png"),
        ("Steam", "https://avatars.steamstatic.com/def.jpg"),
    ]

    with unittest.mock.patch("httpx.AsyncClient", return_value=mock_client):
        hashes, matches = await fetch_and_hash_avatars(sources)

    assert len(hashes) == 2
    assert len(matches) == 1
    assert matches[0].platform_a == "Discord"
    assert matches[0].platform_b == "Steam"
    assert matches[0].hamming_distance <= 2
    assert matches[0].is_match is True
