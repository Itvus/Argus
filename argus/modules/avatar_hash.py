"""Cross-platform avatar perceptual hashing (dHash) and correlation engine for Argus.

Computes 64-bit difference hashes for avatars across platforms (Discord, Steam, GitHub, Gravatar)
and calculates pairwise Hamming distances to prove cross-platform identity matches.
"""

from __future__ import annotations

import asyncio
import io
from typing import Callable, Optional, Tuple

import httpx
from PIL import Image

from argus.models import AvatarHash, AvatarMatch

ProgressCallback = Callable[[str, int, int, str], None]


def compute_dhash(image_bytes: bytes, hash_size: int = 8) -> Optional[int]:
    """Compute 64-bit difference hash (dHash) from raw image bytes.
    
    Resizes image to (hash_size + 1, hash_size), converts to 8-bit grayscale,
    and compares adjacent horizontal pixel intensities.
    """
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            gray = img.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
            pixels = list(gray.tobytes())
            width = hash_size + 1
            diff = [
                pixels[row * width + col] > pixels[row * width + col + 1]
                for row in range(hash_size)
                for col in range(hash_size)
            ]
            return sum(1 << i for i, v in enumerate(diff) if v)
    except Exception:
        return None


def hamming_distance(h1: int, h2: int) -> int:
    """Calculate the Hamming distance (number of differing bits) between two 64-bit hashes."""
    return bin(h1 ^ h2).count("1")


async def fetch_and_hash_avatars(
    avatar_sources: list[Tuple[str, str]],  # [(platform_name, avatar_url)]
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Tuple[list[AvatarHash], list[AvatarMatch]]:
    """Download avatars concurrently, compute perceptual hashes, and compare pairwise matches."""
    if not avatar_sources:
        return [], []

    # Filter out empty or duplicate URLs
    unique_sources: list[Tuple[str, str]] = []
    seen_urls: set[str] = set()
    for plat, url in avatar_sources:
        clean_url = url.strip() if url else ""
        if clean_url and clean_url not in seen_urls and clean_url.startswith(("http://", "https://")):
            seen_urls.add(clean_url)
            unique_sources.append((plat, clean_url))

    if not unique_sources:
        return [], []

    if progress_callback:
        progress_callback("Avatar Correlation", 0, len(unique_sources), f"Hashing {len(unique_sources)} avatar images...")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    }

    hashes: list[AvatarHash] = []

    async with httpx.AsyncClient(timeout=timeout, proxy=proxy, follow_redirects=True) as client:
        async def fetch_and_hash(platform: str, url: str) -> None:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200 and resp.content:
                    h_val = compute_dhash(resp.content)
                    if h_val is not None:
                        hex_str = f"{h_val:016x}"
                        hashes.append(
                            AvatarHash(
                                platform=platform,
                                url=url,
                                dhash=hex_str,
                                dhash_int=h_val,
                            )
                        )
            except Exception:
                pass

        tasks = [fetch_and_hash(plat, u) for plat, u in unique_sources]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Compute pairwise Hamming distances
    matches: list[AvatarMatch] = []
    for i in range(len(hashes)):
        for j in range(i + 1, len(hashes)):
            h_a = hashes[i]
            h_b = hashes[j]
            dist = hamming_distance(h_a.dhash_int, h_b.dhash_int)
            # Distance <= 5 indicates the same image (even if resized or compressed)
            if dist <= 5:
                matches.append(
                    AvatarMatch(
                        platform_a=h_a.platform,
                        url_a=h_a.url,
                        platform_b=h_b.platform,
                        url_b=h_b.url,
                        hamming_distance=dist,
                        is_match=True,
                    )
                )

    return hashes, matches
