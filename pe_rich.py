import sys
import pe


if (len(sys.argv) < 2):
    print('Usage: '+ sys.argv[0] + ' filename')
    exit(0)

filename = sys.argv[1]
with pe.PEFile() as pefile:
    pefile.open(filename)
    rich_hdr = pefile.get_rich_header()

if rich_hdr is None:
    raise pefile.PEFormatError('Failed to get Rich header.')

new_filename = filename + '.rich'
with open(new_filename, "wb") as f:
    f.write(rich_hdr)

for i in range(16, len(rich_hdr) - 8, 8):
    id, vnum = pe.read_val(rich_hdr, i, 4, 2)
    min_ver = id & 0xFFFF
    id >>= 16
    print('Id: {:d}\tVersion: {:d}\tTimes: {:d}'.format(id, min_ver, vnum))
