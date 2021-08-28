import sys
import io
import os.path
import datetime
import hashlib
from math import log2
from collections import Counter
import pe


DATETIME_FMT = '%Y-%m-%d %H:%M:%S'


timestamp_to_str = lambda ts: \
    datetime.datetime.utcfromtimestamp(ts).strftime(DATETIME_FMT) + ' (UTC)'


def get_entropy(data):
    e = 0.
    counter = Counter(data)
    for count in counter.values():
        prob = count / len(data)
        e -= prob * log2(prob)
    return e


if (len(sys.argv) < 2):
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

filename = sys.argv[1]

out_filename = filename + '_pe_info.txt'

with pe.PEFile() as pefile:
    pefile.open(filename)

    with io.open(out_filename, 'wt', encoding='utf-8') as f:
        # File name
        f.write('File name: \"' + os.path.basename(filename) + '\"\n\n')

        # Type
        s = 'PE32'
        if pefile.is_x64:
            s += '+'
        if pefile.is_dll:
            s += ' DLL'
        elif pefile.is_exec:
            s += ' EXE'
        if pefile.is_dotNet:
            s += ' .NET'
        if pefile.is_corrupted:
            s += ' (Corrupted)'
        f.write('Type: ' + s + '\n')

        f.write('\n')

        # DLL Name
        dll_name = pefile.get_export_dll_name()
        if (dll_name is not None):
            f.write('Original DLL name: \"' + dll_name + '\"\n\n')

        # File size
        f.write('File size:    ' + str(pefile.file_size) + '\n')
        f.write('PE file size: ' + str(pefile.pe_file_size) + '\n')
        if (pefile.file_size > pefile.pe_file_size):
            f.write('Overlay size: ' +
                    str(pefile.file_size - pefile.pe_file_size) + '\n')

        f.write('\n')

        # Certificates
        if (pefile.num_certificates != 0):
            f.write('Certificates: ' + str(pefile.num_certificates) + '\n\n')

        # MD5
        m = hashlib.md5()
        m.update(pefile._file_data)
        f.write('MD5:     ' + m.hexdigest() + '\n')

        # SHA-1
        m = hashlib.sha1()
        m.update(pefile._file_data)
        f.write('SHA-1:   ' + m.hexdigest() + '\n')

        # SHA-256
        m = hashlib.sha256()
        m.update(pefile._file_data)
        f.write('SHA-256: ' + m.hexdigest() + '\n')

        # Imphash
        f.write('Imphash: ' + pefile.get_imphash() + '\n')

        # Entropy
        entropy = get_entropy(pefile._file_data)
        f.write('Entropy: {:.3f}\n'.format(entropy))

        f.write('\n')

        # Timestamp in PE header
        timestamp = pefile._read_dword(pefile._img_hdr_pos + 4)
        if (timestamp != 0):
            f.write('PE header timestamp: ' +
                    timestamp_to_str(timestamp) + '\n')

        # Timestamp in export
        if (pefile.datadirs[0][0] >= 0):
            timestamp = pefile._read_dword(pefile.datadirs[0][0] + 4)
            if (timestamp != 0):
                f.write('PE export timestamp: ' +
                        timestamp_to_str(timestamp) + '\n')

        # Timestamp in debug
        if (pefile.datadirs[6][0] >= 0):
            timestamp = pefile._read_dword(pefile.datadirs[6][0] + 4)
            if (timestamp != 0):
                f.write('PE debug timestamp:  ' +
                        timestamp_to_str(timestamp) + '\n')

        f.write('\n')

        # PDB file
        pdb_filename = pefile.get_pdb_filename()
        if (pdb_filename is not None):
            f.write('PDB file name: \"' + pdb_filename + '\"\n')
