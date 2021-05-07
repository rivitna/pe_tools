import struct
from collections import namedtuple
import hashlib

try:
    import api_ord
except (ImportError):
    api_ord = None


MZ_SIGN = 0x5A4D                   # 'MZ'
PE_SIGN = 0x00004550               # 'PE\0\0'
RICH_SIGN1 = 0x68636952            # 'Rich'
RICH_SIGN2 = 0x536E6144            # 'DanS'
DOTNET_METADATA_SIGN = 0x424A5342  # 'BSJB'
RSDS_SIGN = 0x53445352             # 'RSDS'

OPT_HDR64_MAGIC = 0x20B

IMG_FILE_HDR_SIZE = 0x14
SECTION_HDR_SIZE = 0x28
IMPORT_DIR_ENTRY_SIZE = 0x14


PESection = namedtuple('PESection',
[
    'name',
    'rva',
    'vsize',
    'aligned_vsize',
    'pos',
    'psize',
    'aligned_psize',
    'characteristics'
])


def get_data_fmt(size, count):
    assert count > 0, 'Count must be > 0.'
    t = None
    if (size == 1):
        t = 'B'
    elif (size == 2):
        t = 'H'
    elif (size == 4):
        t = 'L'
    elif (size == 8):
        t = 'Q'
    assert t, 'Invalid data size! Must be 1, 2, 4 or 8.'
    fmt = '<'
    if (count > 1):
        fmt += str(count)
    fmt += t
    return fmt


def read_val(data, pos, size, count = 1):
    res = struct.unpack_from(get_data_fmt(size, count), data, pos)
    if (count == 1):
        return res[0]
    return res


def write_val(data, pos, size, val, count = 1):
    struct.pack_into(get_data_fmt(size, count), data, pos, val)


def get_short_libname(lib_name):
    exts = ['ocx', 'sys', 'dll']
    lib_name = lib_name.lower()
    parts = lib_name.rsplit('.', 1)
    if (len(parts) > 1) and (parts[1] in exts):
        return parts[0]
    return lib_name


def get_func_fullname(lib_name, fnc_name):
    if api_ord is None:
        raise SystemError('The \'api_ord\' module is not available')

    if isinstance(fnc_name, int):
        fnc_fullname = api_ord.get_api_func_name_by_ord(lib_name,
                                                        fnc_name,
                                                        True)
        if (fnc_fullname is None):
            raise Exception('Unknown function %s:%d' % (lib_name, fnc_name))
        return fnc_fullname
    return get_short_libname(lib_name) + '.' + fnc_name


class PEFormatError(Exception):
    """PE format error exception."""
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class PEFile(object):

    def __init__(self):
        self.close()


    def __enter__(self):
        self.close()
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


    def close(self):
        self._file_data = None
        self.file_data_changed = None
        self.file_size = None
        self.pe_file_size = None
        self._nt_hdr_pos = None
        self._nt_hdr_size = None
        self._img_hdr_pos = None
        self._opt_hdr_pos = None
        self._opt_hdr_size = None
        self._characteristics = None
        self._section_alignment = None
        self._file_alignment = None
        self.is_corrupted = None
        self.is_exec = None
        self.is_dll = None
        self.is_x64 = None
        self.image_base = None
        self.image_size = None
        self.effective_image_size = None
        self.num_sections = None
        self.sections = None
        self._first_section_hdr_pos = None
        self.datadirs = None
        self._datadirs_pos = None
        self.num_datadirs = None
        self.is_dotNet = None
        self.dotnet_metadata_pos = None
        self.dotnet_metadata_size = None
        self.num_certificates = None
        self.certificates = None


    def _read_data(self, pos, size):
        return self._file_data[pos : pos + size]


    def _read_val(self, pos, size, count = 1):
        return read_val(self._file_data, pos, size, count)


    def _read_byte(self, pos, count = 1):
        return self._read_val(pos, 1, count)


    def _read_word(self, pos, count = 1):
        return self._read_val(pos, 2, count)


    def _read_dword(self, pos, count = 1):
        return self._read_val(pos, 4, count)


    def _read_qword(self, pos, count = 1):
        return self._read_val(pos, 8, count)


    def _write_val(self, pos, size, val, count = 1):
        self._file_data = bytearray(self._file_data)
        write_val(self._file_data, pos, size, val, count)
        self.file_data_changed = True


    def _write_byte(self, pos, val, count = 1):
        self._write_val(pos, 1, val, count)


    def _write_word(self, pos, val, count = 1):
        self._write_val(pos, 2, val, count)


    def _write_dword(self, pos, val, count = 1):
        self._write_val(pos, 4, val, count)


    def _write_qword(self, pos, val, count = 1):
        self._write_val(pos, 8, val, count)


    def _arrange_sections(self):
        if (self.num_sections == 0) or (self.sections is None):
            return False
        sorted(self.sections, key = lambda section : section.rva)


    def _rva_to_filepos(self, rva, size = 1):
        if (rva < self.sections[0].rva):
            if (rva + size <= self.sections[0].pos):
                return rva
            return -1
        for section in self.sections:
            if (section.pos != 0) and (rva >= section.rva):
                offset = rva - section.rva
                if (offset + size <= min(section.aligned_vsize,
                                         section.aligned_psize)):
                    return (section.pos + offset)
        return -1


    def _read_sz(self, pos, is_rva = False):
        if is_rva:
            pos = self._rva_to_filepos(pos)
            if (pos < 0):
                return None
        end_pos = self._file_data.find(0, pos)
        if (end_pos < 0):
            return None
        return self._read_data(pos, end_pos - pos)


    def init(self, file_data):
        # Parse PE header
        self.is_corrupted = False
        self._file_data = file_data
        self.file_size = len(self._file_data)

        mz_sign = self._read_word(0)
        if (mz_sign != MZ_SIGN):
            self.is_corrupted = True
            raise PEFormatError('Invalid MZ signature.')

        self._nt_hdr_pos = self._read_dword(0x3C)
        pe_sign = self._read_dword(self._nt_hdr_pos)
        if (pe_sign != PE_SIGN):
            self.is_corrupted = True
            raise PEFormatError('Invalid PE signature.')

        self.is_corrupted = False
        self.file_data_changed = False
        self._img_hdr_pos = self._nt_hdr_pos + 4
        self.num_sections = self._read_word(self._img_hdr_pos + 2)
        self._opt_hdr_pos = self._img_hdr_pos + IMG_FILE_HDR_SIZE
        self._opt_hdr_size = self._read_word(self._img_hdr_pos + 0x10)
        self._characteristics = self._read_word(self._img_hdr_pos + 0x12)
        self.is_exec = True if (self._characteristics & 0x0002) else False
        self.is_dll = True if (self._characteristics & 0x2000) else False
        self._nt_hdr_size = 4 + IMG_FILE_HDR_SIZE + self._opt_hdr_size
        self._first_section_hdr_pos = self._nt_hdr_pos + self._nt_hdr_size
        self._section_alignment, self._file_alignment = \
            self._read_dword(self._opt_hdr_pos + 0x20, 2)
        if ((self.num_sections == 0) or
            (self._section_alignment < 2) or
            (self._file_alignment < 2) or
            (self._section_alignment < self._file_alignment)):
            self.is_corrupted = True
            raise PEFormatError('Invalid PE file.')
        opt_hdr_magic = self._read_word(self._opt_hdr_pos)
        self.is_x64 = True if (opt_hdr_magic == OPT_HDR64_MAGIC) else False
        if self.is_x64:
            self.image_base = self._read_qword(self._opt_hdr_pos + 0x18)
        else:
            self.image_base = self._read_dword(self._opt_hdr_pos + 0x1C)
        self.image_size = self._read_dword(self._opt_hdr_pos + 0x38)

        # Sections
        self.sections = list()

        effective_image_size = 0

        pos = self._first_section_hdr_pos
        for i in range(self.num_sections):
            s_name = self._read_data(pos, 8)
            i = s_name.find(0)
            if (i >= 0):
                s_name = s_name[:i]
            s_vsize, s_rva, s_psize, s_pos = self._read_dword(pos + 8, 4)
            s_aligned_vsize = (((s_vsize + self._section_alignment - 1) //
                                self._section_alignment) *
                               self._section_alignment)
            s_aligned_psize = (((s_psize + self._file_alignment - 1) //
                                self._file_alignment) *
                               self._file_alignment)
            effective_image_size = max(effective_image_size, s_rva + s_aligned_vsize)
            s_characteristics = self._read_dword(pos + 36)
            self.sections.append(PESection(name = s_name,
                                           rva = s_rva,
                                           vsize = s_vsize,
                                           aligned_vsize = s_aligned_vsize,
                                           pos = s_pos,
                                           psize = s_psize,
                                           aligned_psize = s_aligned_psize,
                                           characteristics = s_characteristics))
            pos += SECTION_HDR_SIZE

        self.effective_image_size = effective_image_size

        self._arrange_sections()

        # Directory
        pos = self._opt_hdr_pos + 0x5C
        if self.is_x64:
            pos += 0x10
        self.num_datadirs = min(16, self._read_dword(pos))
        self.datadirs = list()
        pos += 4
        self._datadirs_pos = pos
        for i in range(self.num_datadirs):
            rva, size = self._read_dword(pos, 2)
            if (i == 4):
                # Certificate directory
                offset = rva if (rva != 0) else -1
            else:
                offset = self._rva_to_filepos(rva, size) if (rva != 0) else -1
            self.datadirs.append((offset, size))
            pos += 8

        # Compute PE file size
        pe_file_size = 0
        for section in self.sections:
            if (section.pos != 0):
                pe_file_size = max(pe_file_size, section.pos + section.psize)
        if (pe_file_size > self.file_size):
            self.is_corrupted = True
        if (len(self.datadirs) > 4):
            # Certificate directory
            cert_dir_pos, cert_dir_size = self.datadirs[4]
            if (cert_dir_pos > 0) and (cert_dir_size != 0):
                if (cert_dir_pos + cert_dir_size > pe_file_size):
                    pe_file_size = cert_dir_pos + cert_dir_size
        self.pe_file_size = pe_file_size

        # Detect .NET managed module
        self.is_dotNet = False
        self.dotnet_metadata_pos = None
        self.dotnet_metadata_size = None
        # COM Runtime directory
        if (len(self.datadirs) > 14):
            clr_hdr_pos, clr_hdr_size = self.datadirs[14]
            if (clr_hdr_pos != -1) and (clr_hdr_size >= 16):
                cb, version, metadata_rva, metadata_size = \
                    self._read_dword(clr_hdr_pos, 4)
                if (cb == clr_hdr_size):
                    metadata_pos = self._rva_to_filepos(metadata_rva,
                                                        metadata_size)
                    if (metadata_pos != -1):
                        sign = self._read_dword(metadata_pos)
                        if (sign == DOTNET_METADATA_SIGN):
                            self.is_dotNet = True
                            self.dotnet_metadata_pos = metadata_pos
                            self.dotnet_metadata_size = metadata_size
                        else:
                            self.is_corrupted = True
                    else:
                        self.is_corrupted = True

        # Certificates
        self.num_certificates = 0
        if (len(self.datadirs) > 4):
            # Certificate directory
            cert_dir_pos, cert_dir_size = self.datadirs[4]
            if ((cert_dir_pos > 0) and
                (cert_dir_size >= 4) and
                (cert_dir_pos + cert_dir_size <= self.file_size)):
                self.certificates = list()
                pos = cert_dir_pos
                size = cert_dir_size
                while (size > 0):
                    cert_size = self._read_dword(pos)
                    if (cert_size < 4):
                        break
                    cert_size = (cert_size + 7) & ~7
                    if (cert_size <= size):
                        self.certificates.append((pos, cert_size))
                        self.num_certificates += 1
                    else:
                        break
                    pos += cert_size
                    size -= cert_size


    def open(self, file_name):
        with open(file_name, 'rb') as f:
            self.init(f.read())


    def write_to_file(self, file_name):
        with open(file_name, 'wb') as f:
            f.write(self._file_data)


    def get_rich_header(self):
        for pos in range(self._nt_hdr_pos - 8, 0x44, -4):
            sign = self._read_dword(pos)
            if (sign == RICH_SIGN1):
                break
        else:
            return None
        xor_mask = self._read_dword(pos + 4)
        end_pos = pos + 8
        for pos in range(pos - 4, 0x40, -4):
            sign = self._read_dword(pos) ^ xor_mask
            if (sign == RICH_SIGN2):
                break
        else:
            return None
        rich_hdr = bytearray(self._read_data(pos, end_pos - pos))
        for pos in range(0, (end_pos - 8) - pos, 4):
            v = read_val(rich_hdr, pos, 4, 1) ^ xor_mask
            write_val(rich_hdr, pos, 4, v, 1)
        return bytes(rich_hdr)


    def _enum_import_table(self, only_libs = False):
        if (self.num_datadirs < 2):
            return
        # Import directory
        dir_entry_pos = self.datadirs[1][0] - IMPORT_DIR_ENTRY_SIZE
        while True:
            dir_entry_pos += IMPORT_DIR_ENTRY_SIZE
            lookup_table_rva = self._read_dword(dir_entry_pos)
            name_rva, thunk_table_rva = \
                self._read_dword(dir_entry_pos + 12, 2)
            if ((lookup_table_rva == 0) and
                (name_rva == 0) and
                (thunk_table_rva == 0)):
                break
            if (name_rva == 0):
                continue
            lib_name = self._read_sz(name_rva, True)
            if (lib_name is None) or (lib_name == b''):
                continue
            if only_libs:
                yield lib_name.decode('ascii')
            if (lookup_table_rva == 0):
                lookup_table_rva = thunk_table_rva
            pos = self._rva_to_filepos(lookup_table_rva, 4)
            if (pos < 0):
                continue
            entry_size = 8 if self.is_x64 else 4
            ord_imp_bit_mask = 1 << (8 * entry_size - 1)
            while True:
                entry = self._read_val(pos, entry_size)
                if (entry == 0):
                    break
                if ((entry & ord_imp_bit_mask) == 0):
                    fnc_name = self._read_sz((entry & 0x7FFFFFFF) + 2,
                                             True)
                    if (fnc_name is not None) and (fnc_name != b''):
                        yield (lib_name.decode('ascii'), fnc_name.decode('ascii'))
                else:
                    yield (lib_name.decode('ascii'), int(entry & 0x7FFF))
                pos += entry_size


    def _enum_export_table(self):
        if (self.num_datadirs == 0):
            return
        # Export directory
        dir_entry_pos = self.datadirs[0][0]
        num_functions, num_names, addr_table_rva, name_table_rva, \
            ord_table_rva = self._read_dword(dir_entry_pos + 20, 5)
        name_table_pos = self._rva_to_filepos(name_table_rva, 4 * num_names)
        if (name_table_pos < 0):
            return
        ord_table_pos = self._rva_to_filepos(ord_table_rva, 2 * num_names)
        if (ord_table_pos < 0):
            return
        addr_table_pos = self._rva_to_filepos(addr_table_rva,
                                              4 * num_functions)
        if (addr_table_pos < 0):
            return
        for i in range(num_names):
            fnc_ord = self._read_word(ord_table_pos + 2 * i)
            if (fnc_ord >= num_functions):
                continue
            fnc_rva = self._read_dword(addr_table_pos + 4 * fnc_ord)
            fnc_name_rva = self._read_dword(name_table_pos + 4 * i)
            fnc_name = self._read_sz(fnc_name_rva, True)
            yield (fnc_name.decode('ascii'), fnc_ord, fnc_rva)


    def get_imphash(self):
        funcs = list()
        for lib_name, fnc_name in self._enum_import_table(False):
            funcs.append(get_func_fullname(lib_name, fnc_name).lower())
        impstr = ','.join(funcs)
        m = hashlib.md5()
        m.update(bytes(impstr, 'utf-8'))
        return m.hexdigest()


    def get_export_dll_name(self):
        if (self.num_datadirs == 0):
            return None
        # Export directory
        export_dir_pos = self.datadirs[0][0]
        if (export_dir_pos < 0):
            return None
        dll_name_rva = self._read_dword(export_dir_pos + 12)
        if (dll_name_rva == 0):
            return None
        dll_name = self._read_sz(dll_name_rva, True)
        if (dll_name is not None):
            return dll_name.decode('ascii')
        return None


    def get_pdb_filename(self):
        if (self.num_datadirs < 7):
            return None
        # Debug directory
        debug_dir_pos = self.datadirs[6][0]
        if (debug_dir_pos < 0):
            return None
        debug_data_size = self._read_dword(debug_dir_pos + 16)
        debug_data_pos = self._read_dword(debug_dir_pos + 24)
        if (debug_data_pos == 0) or (debug_data_size == 0):
            return None
        sign = self._read_dword(debug_data_pos)
        if (sign != RSDS_SIGN):
            return None
        return self._read_sz(debug_data_pos + 24).decode('utf-8')
