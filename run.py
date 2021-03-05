import datetime
import os
import re
import subprocess
import glob

if __name__ == "__main__":

    # calculate time
    current_time = datetime.datetime.now()
    print_time = current_time.strftime('%Y.%m.%d-%H.%M')

    report_format = 'tex-plus'

    # setup files
    root_dir = "shared"
    report_dir = os.path.join(root_dir, "reports", print_time)
    xml_dir = os.path.join(root_dir, "xml_files", print_time)
    # check if directory exists
    if os.path.isdir(xml_dir) == False:
        os.mkdir(xml_dir)
    if os.path.isdir(report_dir) == False:
        os.mkdir(report_dir)

    # read ips
    ips_file = os.path.join(root_dir, 'ips.txt')
    with open(ips_file, 'r') as ips:
        for line in ips.readlines():
            ip = line.strip()
            latest_time = datetime.datetime.now()
            file_time = latest_time.strftime('%Y.%m.%d-%H.%M.%S')

            xml_file = os.path.join(xml_dir, '{0}-{1}.xml'.format(ip, file_time))
            report_file = os.path.join(report_dir, "{0}-{1}.tex".format(ip, file_time))

            cmd = "nmap -sV -v -oX \"{0}\" --script vulners --script ssl-enum-ciphers {1}".format(xml_file, ip)
            subprocess.run(cmd)

            # make a nice latex report
            cmd = "venv\Scripts\python.exe output_report.py {0} {1} {2} {3}".format(xml_file, report_file, ip, report_format)
            subprocess.run(cmd)

    if report_format == 'tex' or report_format == 'tex-plus':
        report_files = os.path.join(report_dir, "*.tex")
        texs = glob.glob(report_files)

        # cleanup reports
        for tex in texs:
            r = ''
            with open(tex, 'r') as orig_report:
                r = orig_report.read()

            r = re.sub(r'[_]', r'\\_', r, 0)
            r = re.sub(r'[$]', r'\\$', r, 0)
            r = re.sub(r'[#]', r'\\#', r, 0)
            r = re.sub(r'[%]', r'\\%', r, 0)
            with open(report_file, 'w') as new_report:
                new_report.write(r)

            cmd = 'pdflatex -quiet -output-directory {0} {1}'.format(report_dir, tex)
            subprocess.run(cmd)
