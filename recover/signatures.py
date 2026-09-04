import io
import zipfile
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

@dataclass
class SignatureDef:
    file_type: str
    extension: str
    headers: List[bytes]
    footer: Optional[bytes]
    max_size: int
    category: str
    requires_container_parser: bool = False

def validate_png_structure(data: bytes) -> bool:
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    offset = 8
    while offset + 8 <= len(data):
        chunk_len = int.from_bytes(data[offset:offset+4], byteorder="big")
        chunk_type = data[offset+4:offset+8]
        offset += 8 + chunk_len + 4
        if chunk_type == b"IEND":
            return True
    return False

def validate_zip_structure(data: bytes) -> tuple[bool, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            namelist = zf.namelist()
            if "[Content_Types].xml" in namelist:
                if any(n.startswith("word/") for n in namelist):
                    return True, "docx"
                if any(n.startswith("xl/") for n in namelist):
                    return True, "xlsx"
                if any(n.startswith("ppt/") for n in namelist):
                    return True, "pptx"
            return zf.testzip() is None, "zip"
    except Exception:
        return False, "zip"

def validate_pdf_structure(data: bytes) -> bool:
    return data.startswith(b"%PDF-") and b"%%EOF" in data

def validate_sqlite_structure(data: bytes) -> tuple[bool, int]:
    if len(data) < 100 or not data.startswith(b"SQLite format 3\x00"):
        return False, 0
    page_size = int.from_bytes(data[16:18], byteorder="big")
    if page_size == 1:
        page_size = 65536
    page_count = int.from_bytes(data[28:32], byteorder="big")
    total_size = page_size * page_count if (page_size > 0 and page_count > 0) else len(data)
    return True, total_size

SIGNATURE_DATABASE: List[SignatureDef] = [
    SignatureDef(
        file_type="JPEG Image",
        extension="jpg",
        headers=[b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xee", b"\xff\xd8\xff\xdb"],
        footer=b"\xff\xd9",
        max_size=30 * 1024 * 1024,
        category="Images"
    ),
    SignatureDef(
        file_type="PNG Image",
        extension="png",
        headers=[b"\x89PNG\r\n\x1a\n"],
        footer=b"\x49\x45\x4e\x44\xae\x42\x60\x82",
        max_size=30 * 1024 * 1024,
        category="Images"
    ),
    SignatureDef(
        file_type="PDF Document",
        extension="pdf",
        headers=[b"%PDF-"],
        footer=b"%%EOF",
        max_size=100 * 1024 * 1024,
        category="Documents"
    ),
    SignatureDef(
        file_type="ZIP / Office Container",
        extension="zip",
        headers=[b"PK\x03\x04"],
        footer=b"PK\x05\x06",
        max_size=250 * 1024 * 1024,
        category="Documents"
    ),
    SignatureDef(
        file_type="MP4 / ISO Media Video",
        extension="mp4",
        headers=[b"ftypmp42", b"ftypisom", b"ftypMSNV", b"ftypM4V "],
        footer=None,
        max_size=500 * 1024 * 1024,
        category="Videos",
        requires_container_parser=True
    ),
    SignatureDef(
        file_type="SQLite Database",
        extension="sqlite",
        headers=[b"SQLite format 3\x00"],
        footer=None,
        max_size=500 * 1024 * 1024,
        category="Databases",
        requires_container_parser=True
    )
]
