import io
from typing import Optional, Tuple

class AtomCarver:
    KNOWN_ATOMS = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta"}

    @classmethod
    def parse_mp4_stream(cls, stream: io.BufferedReader, start_offset: int, max_size: int) -> Tuple[bool, int]:
        stream.seek(start_offset)
        total_length = 0
        has_ftyp = False
        has_mdat_or_moov = False

        while total_length < max_size:
            header_bytes = stream.read(8)
            if len(header_bytes) < 8:
                break

            atom_size = int.from_bytes(header_bytes[0:4], byteorder="big")
            atom_type = header_bytes[4:8]

            if total_length == 0:
                if atom_type != b"ftyp":
                    return False, 0
                has_ftyp = True

            if atom_type in [b"moov", b"mdat"]:
                has_mdat_or_moov = True

            if atom_size == 1:
                # 64-bit extended size box
                ext_bytes = stream.read(8)
                if len(ext_bytes) < 8:
                    break
                atom_size = int.from_bytes(ext_bytes, byteorder="big")
                total_length += 16
                seek_jump = atom_size - 16
            elif atom_size == 0:
                # Extends to end of media stream
                break
            elif atom_size >= 8:
                total_length += atom_size
                seek_jump = atom_size - 8
            else:
                break

            if atom_type not in cls.KNOWN_ATOMS and total_length > 1024 * 1024:
                break

            if seek_jump > 0:
                stream.seek(seek_jump, io.SEEK_CUR)

            if has_ftyp and has_mdat_or_moov and atom_type in [b"moov", b"mdat"] and total_length > 16:
                peek_next = stream.read(8)
                if len(peek_next) < 8 or peek_next[4:8] not in cls.KNOWN_ATOMS:
                    return True, total_length
                stream.seek(-len(peek_next), io.SEEK_CUR)

        return (has_ftyp and has_mdat_or_moov), total_length
