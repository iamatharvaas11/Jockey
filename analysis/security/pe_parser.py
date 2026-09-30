import struct
import math
from typing import Dict, Any, List, Union

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

def calculate_section_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte array."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

class PEFile:
    """
    Pure Python PE parser using struct.
    Parses headers, sections, imports, and exports.
    """
    def __init__(self, filepath_or_bytes: Union[str, bytes]):
        if isinstance(filepath_or_bytes, str):
            with open(filepath_or_bytes, 'rb') as f:
                self.data = f.read()
            self.filepath = filepath_or_bytes
        else:
            self.data = filepath_or_bytes
            self.filepath = None
            
        self.dos_header: Dict[str, int] = {}
        self.coff_header: Dict[str, int] = {}
        self.optional_header: Dict[str, Any] = {}
        self.sections: List[Dict[str, Any]] = []
        self.imports: Dict[str, List[str]] = {}
        self.exports: List[str] = []
        
        self._parse()

    def _parse(self):
        if len(self.data) < 64:
            return
            
        e_magic = self.data[0:2]
        if e_magic != b'MZ':
            return
            
        self.dos_header['e_lfanew'] = struct.unpack('<I', self.data[60:64])[0]
        pe_offset = self.dos_header['e_lfanew']
        if len(self.data) < pe_offset + 24:
            return
            
        pe_sig = self.data[pe_offset:pe_offset+4]
        if pe_sig != b'PE\x00\x00':
            return
            
        coff_offset = pe_offset + 4
        machine, num_sections, timestamp, ptr_sym, num_sym, size_opt, charac = struct.unpack('<HHIIIHH', self.data[coff_offset:coff_offset+20])
        self.coff_header = {
            'Machine': machine,
            'NumberOfSections': num_sections,
            'TimeDateStamp': timestamp,
            'SizeOfOptionalHeader': size_opt,
            'Characteristics': charac
        }
        
        opt_offset = coff_offset + 20
        magic = struct.unpack('<H', self.data[opt_offset:opt_offset+2])[0]
        self.optional_header['Magic'] = magic
        
        if magic == 0x10B: # PE32
            (image_base, section_align, file_align, major_os, minor_os, major_image, minor_image, 
             major_sub, minor_sub, win32_ver, size_image, size_headers) = struct.unpack('<IIIIHHHHHHIII', self.data[opt_offset+28:opt_offset+68])
            self.optional_header['ImageBase'] = image_base
            self.optional_header['SectionAlignment'] = section_align
            self.optional_header['FileAlignment'] = file_align
            self.optional_header['SizeOfImage'] = size_image
            self.optional_header['SizeOfHeaders'] = size_headers
            
            num_rva = struct.unpack('<I', self.data[opt_offset+92:opt_offset+96])[0]
            self.optional_header['NumberOfRvaAndSizes'] = num_rva
            data_dir_offset = opt_offset + 96
        elif magic == 0x20B: # PE32+
            (image_base, section_align, file_align, major_os, minor_os, major_image, minor_image, 
             major_sub, minor_sub, win32_ver, size_image, size_headers) = struct.unpack('<QIIHHHHHHIII', self.data[opt_offset+24:opt_offset+64])
            self.optional_header['ImageBase'] = image_base
            self.optional_header['SectionAlignment'] = section_align
            self.optional_header['FileAlignment'] = file_align
            self.optional_header['SizeOfImage'] = size_image
            self.optional_header['SizeOfHeaders'] = size_headers
            
            num_rva = struct.unpack('<I', self.data[opt_offset+108:opt_offset+112])[0]
            self.optional_header['NumberOfRvaAndSizes'] = num_rva
            data_dir_offset = opt_offset + 112
        else:
            return
            
        self.optional_header['DataDirectory'] = []
        for i in range(min(num_rva, 16)):
            if len(self.data) < data_dir_offset + i*8 + 8:
                break
            rva, size = struct.unpack('<II', self.data[data_dir_offset+i*8:data_dir_offset+i*8+8])
            self.optional_header['DataDirectory'].append({'VirtualAddress': rva, 'Size': size})
            
        sections_offset = opt_offset + self.coff_header['SizeOfOptionalHeader']
        for i in range(num_sections):
            if len(self.data) < sections_offset + i*40 + 40:
                break
            sec_data = self.data[sections_offset+i*40:sections_offset+i*40+40]
            name, vsize, vaddr, rawsize, rawptr, relptr, lineno_ptr, num_rel, num_lin, charac = struct.unpack('<8sIIIIIIHHI', sec_data)
            self.sections.append({
                'Name': name.split(b'\x00')[0].decode('ascii', errors='ignore'),
                'VirtualSize': vsize,
                'VirtualAddress': vaddr,
                'SizeOfRawData': rawsize,
                'PointerToRawData': rawptr,
                'Characteristics': charac
            })

        if len(self.optional_header['DataDirectory']) > 1:
            imp_dir = self.optional_header['DataDirectory'][1]
            if imp_dir['VirtualAddress'] != 0:
                self._parse_imports(imp_dir['VirtualAddress'])
                
        if len(self.optional_header['DataDirectory']) > 0:
            exp_dir = self.optional_header['DataDirectory'][0]
            if exp_dir['VirtualAddress'] != 0:
                self._parse_exports(exp_dir['VirtualAddress'])
                
    def rva_to_offset(self, rva: int) -> int:
        """Converts an RVA to a file offset based on section headers."""
        for sec in self.sections:
            if sec['VirtualAddress'] <= rva < sec['VirtualAddress'] + max(sec['VirtualSize'], sec['SizeOfRawData']):
                return rva - sec['VirtualAddress'] + sec['PointerToRawData']
        return 0

    def _parse_imports(self, rva: int):
        offset = self.rva_to_offset(rva)
        if offset == 0: return
        is_64 = self.optional_header.get('Magic') == 0x20B
        ptr_size = 8 if is_64 else 4
        ptr_fmt = '<Q' if is_64 else '<I'
        
        while True:
            if offset + 20 > len(self.data): break
            ilt_rva, timestamp, forwarder, name_rva, iat_rva = struct.unpack('<IIIII', self.data[offset:offset+20])
            if ilt_rva == 0 and name_rva == 0: break
            
            name_off = self.rva_to_offset(name_rva)
            if name_off == 0: break
            end = self.data.find(b'\x00', name_off)
            if end == -1: break
            dll_name = self.data[name_off:end].decode('ascii', errors='ignore').lower()
            
            self.imports[dll_name] = []
            
            thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
            thunk_off = self.rva_to_offset(thunk_rva)
            if thunk_off == 0:
                offset += 20
                continue
                
            while True:
                if thunk_off + ptr_size > len(self.data): break
                thunk_val = struct.unpack(ptr_fmt, self.data[thunk_off:thunk_off+ptr_size])[0]
                if thunk_val == 0: break
                
                ordinal_flag = (1 << 63) if is_64 else (1 << 31)
                if not (thunk_val & ordinal_flag):
                    hint_off = self.rva_to_offset(thunk_val & 0x7FFFFFFF)
                    if hint_off > 0 and hint_off + 2 < len(self.data):
                        func_name_end = self.data.find(b'\x00', hint_off + 2)
                        if func_name_end != -1:
                            func_name = self.data[hint_off+2:func_name_end].decode('ascii', errors='ignore')
                            self.imports[dll_name].append(func_name)
                
                thunk_off += ptr_size
            offset += 20

    def _parse_exports(self, rva: int):
        offset = self.rva_to_offset(rva)
        if offset == 0 or offset + 40 > len(self.data): return
        
        _, _, _, _, _, _, num_names, _, _, names_rva, _ = struct.unpack('<IIHHIIIIIII', self.data[offset:offset+40])
        
        names_off = self.rva_to_offset(names_rva)
        if names_off == 0: return
        
        for i in range(num_names):
            if names_off + i*4 + 4 > len(self.data): break
            name_ptr_rva = struct.unpack('<I', self.data[names_off+i*4:names_off+i*4+4])[0]
            name_ptr_off = self.rva_to_offset(name_ptr_rva)
            if name_ptr_off > 0:
                end = self.data.find(b'\x00', name_ptr_off)
                if end != -1:
                    func_name = self.data[name_ptr_off:end].decode('ascii', errors='ignore')
                    self.exports.append(func_name)
