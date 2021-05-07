import sys
import pe


if (len(sys.argv) < 2):
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

filename = sys.argv[1]
new_filename = filename + '.cut'

with pe.PEFile() as pefile:
    pefile.open(filename)

    print('Effective PE file size: ' + str(pefile.file_size))
    print('PE file size:           ' + str(pefile.pe_file_size))

    if (pefile.file_size > pefile.pe_file_size):
        del pefile._file_data[pefile.pe_file_size:]
        pefile.write_to_file(new_filename)
        print('PE file overlay cutted.')
