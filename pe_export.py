import sys
import pe


def get_pe_export(filename):
    export_list = {}

    with pe.PEFile() as pefile:
        pefile.open(filename)

        for fnc_name, fnc_ord, fnc_addr in pefile._enum_export_table():
            export_list[pefile.image_base + fnc_addr] = fnc_name

    return export_list


if (len(sys.argv) < 2):
    print('Usage: '+ sys.argv[0] + ' filename')
    sys.exit(0)

filename = sys.argv[1]

export_list = get_pe_export(filename)

for fnc_addr in export_list:
    print('%08X\t%s' % (fnc_addr, export_list[fnc_addr]))
