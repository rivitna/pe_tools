import sys
import hashlib
import pe


if (len(sys.argv) < 2):
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

filename = sys.argv[1]
with pe.PEFile() as pefile:
    pefile.open(filename)

    # MD5
    m = hashlib.md5()
    m.update(pefile._file_data)
    print('MD5: ' + m.hexdigest())

    # SHA-1
    m = hashlib.sha1()
    m.update(pefile._file_data)
    print('SHA-1: ' + m.hexdigest())

    # SHA-256
    m = hashlib.sha256()
    m.update(pefile._file_data)
    print('SHA-256: ' + m.hexdigest())

    # Imphash
    print('Imphash: ' + pefile.get_imphash())
