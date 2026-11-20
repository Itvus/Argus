"""Avatar image EXIF metadata and technical inspection module."""

from __future__ import annotations

import io
from typing import Callable, Optional
import httpx
from PIL import ExifTags, Image

from argus.models import ImageMetadataReport, ModuleStatus


async def inspect_avatar_metadata(
    avatar_sources: list[tuple[str, str]],
    timeout: int = 10,
    proxy: Optional[str] = None,
    progress_callback: Optional[Callable[[str, int, int, str], None]] = None,
) -> tuple[list[ImageMetadataReport], ModuleStatus]:
    """Download avatars and inspect for embedded EXIF tags, dimensions, format, and software signatures."""
    if not avatar_sources:
        return [], ModuleStatus(
            module_name="Image Metadata / EXIF",
            status="skipped",
            message="No avatar sources available to inspect",
        )

    if progress_callback:
        progress_callback("Image Metadata", 0, len(avatar_sources), "Inspecting image metadata...")

    reports: list[ImageMetadataReport] = []
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "headers": {"User-Agent": "Argus-OSINT/1.0"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        for idx, (platform, url) in enumerate(avatar_sources, start=1):
            if progress_callback:
                progress_callback("Image Metadata", idx, len(avatar_sources), f"Inspecting {platform} avatar")
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and resp.content:
                    data = resp.content
                    file_size = len(data)
                    with Image.open(io.BytesIO(data)) as img:
                        fmt = img.format
                        dimensions = f"{img.width}x{img.height}"
                        color_mode = img.mode

                        exif_data = img.getexif()
                        exif_tags: dict[str, str] = {}
                        make: Optional[str] = None
                        model: Optional[str] = None
                        software: Optional[str] = None
                        datetime_orig: Optional[str] = None

                        if exif_data:
                            for tag_id, val in exif_data.items():
                                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                                str_val = str(val).strip()
                                exif_tags[tag_name] = str_val
                                if tag_name == "Make":
                                    make = str_val
                                elif tag_name == "Model":
                                    model = str_val
                                elif tag_name == "Software":
                                    software = str_val
                                elif tag_name in ("DateTime", "DateTimeOriginal"):
                                    datetime_orig = str_val

                        reports.append(
                            ImageMetadataReport(
                                platform=platform,
                                url=url,
                                has_exif=bool(exif_tags),
                                make=make,
                                model=model,
                                software=software,
                                datetime_original=datetime_orig,
                                dimensions=dimensions,
                                color_mode=color_mode,
                                format=fmt,
                                file_size_bytes=file_size,
                                exif_tags=exif_tags,
                            )
                        )
            except Exception:
                continue

    status = "success" if reports else "no_hits"
    msg = f"Inspected {len(reports)} avatars ({sum(1 for r in reports if r.has_exif)} had embedded EXIF tags)"
    return reports, ModuleStatus(module_name="Image Metadata / EXIF", status=status, message=msg)
