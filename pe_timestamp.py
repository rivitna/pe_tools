import sys
import time
import datetime
import pe


DATETIME_FMT = '%Y-%m-%d %H:%M:%S'


def str_to_timestamp(s):
    return int(time.mktime(time.strptime(s, DATETIME_FMT)) - time.timezone)

def timestamp_to_str(ts):
    return datetime.datetime.utcfromtimestamp(ts).strftime(DATETIME_FMT) + \
           ' (UTC)'

if (len(sys.argv) < 2):
    print('Usage: '+ sys.argv[0] + ' filename [datetime]')
    sys.exit(0)


timestamp = str_to_timestamp(sys.argv[2]) if (len(sys.argv) >= 3) else None

filename = sys.argv[1]

with pe.PEFile() as pefile:
    pefile.open(filename)

    # Timestamp in PE header
    old_timestamp = pefile._read_dword(pefile._img_hdr_pos + 4)
    print('PE header timestamp: ' + timestamp_to_str(old_timestamp))
    if (timestamp is not None):
        pefile._write_dword(pefile._img_hdr_pos + 4, timestamp)
        print('New PE header timestamp: ' + timestamp_to_str(timestamp))

    # Timestamp in export
    if (pefile.datadirs[0][0] >= 0):
        old_timestamp = pefile._read_dword(pefile.datadirs[0][0] + 4)
        if (old_timestamp != 0):
            print('PE export timestamp: ' + timestamp_to_str(old_timestamp))
            if (timestamp is not None):
                pefile._write_dword(pefile.datadirs[0][0] + 4, timestamp)
                print('New PE export timestamp: ' + \
                      timestamp_to_str(timestamp))

    # Timestamp in debug
    if (pefile.datadirs[6][0] >= 0):
        old_timestamp = pefile._read_dword(pefile.datadirs[6][0] + 4)
        if (old_timestamp != 0):
            print('PE debug timestamp: ' + timestamp_to_str(old_timestamp))
            if (timestamp is not None):
                pefile._write_dword(pefile.datadirs[6][0] + 4, timestamp)
                print('New PE debug timestamp: ' + \
                      timestamp_to_str(timestamp))

    if pefile.file_data_changed:
        # Write binary data to new PE file
        pefile.write_to_file(filename)
