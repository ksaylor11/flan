import datetime
import os
import subprocess
import re

if __name__ == "__main__":

    # calculate time
    current_time = datetime.datetime.now()
    print_time = current_time.strftime('%Y.%m.%d-%H.%M')

    # setup files
    root_dir = "shared"
    xml_dir = os.path.join(root_dir, "xml_files", print_time)
    # check if directory exists
    if os.path.isdir(xml_dir) == False:
        os.mkdir(xml_dir)
    report_file = os.path.join(root_dir, "reports", "{0}.html".format(print_time))

    # read ips
    ips_file = os.path.join(root_dir, 'ips.txt')
    with open(ips_file, 'r') as ips:
        for line in ips.readlines():
            print(line)
            latest_time = datetime.datetime.now()
            file_time = latest_time.strftime('%Y.%m.%d-%H.%M.%S')
            filename = os.path.join(xml_dir, '{0}.xml'.format(file_time))
            cmd = "nmap -sV -v -oX \"{0}\" --script vulners --script ssl-enum-ciphers {1} ".format(filename, line)
            subprocess.run(cmd)

    # make a nice latex report
    cmd = "python output_report.py {0} {1} {2} html".format(xml_dir, report_file, ips_file)
    subprocess.run(cmd)

    # cleanup report
    r = ''
    with open(report_file, 'r') as orig_report:
        r = orig_report.read()

    r = re.sub(r'[_]', r'\\_', r, 0)
    r = re.sub(r'[$]', r'\\$', r, 0)
    r = re.sub(r'[#]', r'\\#', r, 0)
    r = re.sub(r'[%]', r'\\%', r, 0)
    with open(report_file, 'w') as new_report:
        new_report.write(r)

