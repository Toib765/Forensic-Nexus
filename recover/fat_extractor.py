import struct
from typing import Dict, List, Tuple, Any

class FatExtractor:
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.is_fat = False
        self.bytes_per_sec = 512
        self.sec_per_clus = 8
        self.reserved_sec_cnt = 32
        self.num_fats = 2
        self.fat_size = 0
        self.root_clus = 2
        self.data_start_byte = 0
        self.total_clusters = 0

    def parse_boot_sector(self) -> bool:
        try:
            with open(self.target_path, "rb") as f:
                bs = f.read(512)
                if len(bs) < 512 or bs[510:512] != b"\x55\xaa":
                    return False

                self.bytes_per_sec = struct.unpack_from("<H", bs, 11)[0]
                self.sec_per_clus = bs[13]
                self.reserved_sec_cnt = struct.unpack_from("<H", bs, 14)[0]
                self.num_fats = bs[16]
                
                total_sec_16 = struct.unpack_from("<H", bs, 19)[0]
                total_sec_32 = struct.unpack_from("<I", bs, 32)[0]
                total_sectors = total_sec_16 if total_sec_16 != 0 else total_sec_32
                
                fat_size_16 = struct.unpack_from("<H", bs, 22)[0]
                fat_size_32 = struct.unpack_from("<I", bs, 36)[0] if len(bs) >= 40 else 0
                self.fat_size = fat_size_16 if fat_size_16 != 0 else fat_size_32

                if self.bytes_per_sec == 0 or self.sec_per_clus == 0 or self.fat_size == 0:
                    return False

                if fat_size_32 != 0:
                    self.root_clus = struct.unpack_from("<I", bs, 44)[0]
                
                fat_start_sec = self.reserved_sec_cnt
                data_start_sec = fat_start_sec + (self.num_fats * self.fat_size)
                self.data_start_byte = data_start_sec * self.bytes_per_sec
                
                data_sectors = total_sectors - data_start_sec
                self.total_clusters = data_sectors // self.sec_per_clus
                self.is_fat = True
                return True
        except Exception:
            self.is_fat = False
            return False

    def get_cluster_allocation_map(self) -> Tuple[List[Dict[str, Any]], List[Tuple[int, int]]]:
        """
        Parses FAT entries.
        Returns:
            - live_files: List of existing directory records.
            - unallocated_ranges: List of (start_byte, end_byte) corresponding to unallocated space.
        """
        if not self.is_fat and not self.parse_boot_sector():
            # If target lacks valid FAT headers, treat entire byte-space as unallocated
            import os
            return [], [(0, os.path.getsize(self.target_path))]

        cluster_size = self.bytes_per_sec * self.sec_per_clus
        allocated_clusters = set()
        live_files = []

        try:
            with open(self.target_path, "rb") as f:
                # Read FAT1 table
                fat_start_byte = self.reserved_sec_cnt * self.bytes_per_sec
                f.seek(fat_start_byte)
                fat_table_raw = f.read(self.fat_size * self.bytes_per_sec)

                # Collect unallocated cluster indices
                unallocated_clusters = []
                for clus_idx in range(2, min(self.total_clusters + 2, len(fat_table_raw) // 4)):
                    entry = struct.unpack_from("<I", fat_table_raw, clus_idx * 4)[0] & 0x0FFFFFFF
                    if entry == 0:
                        unallocated_clusters.append(clus_idx)
                    else:
                        allocated_clusters.add(clus_idx)

                # Parse Directory Entries to list active files
                root_offset = self.data_start_byte + ((self.root_clus - 2) * cluster_size)
                f.seek(root_offset)
                dir_bytes = f.read(cluster_size * 4)

                for idx in range(0, len(dir_bytes), 32):
                    entry = dir_bytes[idx:idx+32]
                    if len(entry) < 32 or entry[0] in (0x00, 0xE5):
                        continue
                    attr = entry[11]
                    if attr in (0x0F, 0x10):  # Skip LFN and Directories
                        continue
                    
                    raw_name = entry[0:8].decode("latin-1", errors="ignore").strip()
                    raw_ext = entry[8:11].decode("latin-1", errors="ignore").strip()
                    file_name = f"{raw_name}.{raw_ext}".strip(".")
                    file_size = struct.unpack_from("<I", entry, 28)[0]
                    first_cluster = (struct.unpack_from("<H", entry, 20)[0] << 16) | struct.unpack_from("<H", entry, 26)[0]

                    if file_size > 0:
                        live_files.append({
                            "file_name": file_name,
                            "size_bytes": file_size,
                            "first_cluster": first_cluster,
                            "is_deleted": False
                        })

            # Convert unallocated cluster blocks into contiguous byte ranges
            unallocated_ranges: List[Tuple[int, int]] = []
            if unallocated_clusters:
                start_c = unallocated_clusters[0]
                prev_c = start_c

                for c in unallocated_clusters[1:]:
                    if c == prev_c + 1:
                        prev_c = c
                    else:
                        s_byte = self.data_start_byte + ((start_c - 2) * cluster_size)
                        e_byte = self.data_start_byte + ((prev_c - 1) * cluster_size)
                        unallocated_ranges.append((s_byte, e_byte))
                        start_c = c
                        prev_c = c
                
                s_byte = self.data_start_byte + ((start_c - 2) * cluster_size)
                e_byte = self.data_start_byte + ((prev_c - 1) * cluster_size)
                unallocated_ranges.append((s_byte, e_byte))

            return live_files, unallocated_ranges

        except Exception:
            import os
            return [], [(0, os.path.getsize(self.target_path))]
