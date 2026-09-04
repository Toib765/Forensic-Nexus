import math
from typing import Dict, List, Any

class EntropyScanner:
    @staticmethod
    def calculate_block_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        
        entropy = 0.0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @classmethod
    def scan_media_entropy(cls, target_path: str, block_size: int = 64 * 1024) -> Dict[str, Any]:
        """Scans disk in blocks and returns classification profile."""
        total_blocks = 0
        zeroed_blocks = 0
        text_structured_blocks = 0
        high_entropy_blocks = 0
        sample_entropy_map: List[Dict[str, Any]] = []

        with open(target_path, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break
                
                ent = cls.calculate_block_entropy(chunk)
                total_blocks += 1

                if ent == 0.0:
                    zeroed_blocks += 1
                    classification = "ZEROED_SANITIZED"
                elif ent < 5.0:
                    text_structured_blocks += 1
                    classification = "STRUCTURED_UNCOMPRESSED"
                else:
                    high_entropy_blocks += 1
                    classification = "COMPRESSED_OR_ENCRYPTED"

                if total_blocks <= 64:  # Sample for manifest map
                    sample_entropy_map.append({
                        "block_index": total_blocks,
                        "byte_offset": offset,
                        "entropy": ent,
                        "classification": classification
                    })
                offset += len(chunk)

        exhaustion_pct = round(((zeroed_blocks + high_entropy_blocks) / max(total_blocks, 1)) * 100.0, 2)

        return {
            "total_blocks_scanned": total_blocks,
            "zeroed_blocks": zeroed_blocks,
            "structured_blocks": text_structured_blocks,
            "compressed_or_encrypted_blocks": high_entropy_blocks,
            "carving_exhaustion_confidence_pct": exhaustion_pct,
            "sample_map": sample_entropy_map
        }
