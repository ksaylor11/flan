from typing import Any, Dict

from contrib.descriptions import VulnDescriptionProvider
from contrib.internal_types import ScanResult, SeverityLevels, TlsScanResult, TlS_Grade
from contrib.report_builders import PlusReportBuilder

__all__ = ['PlusLatexReportBuilder']


class PlusLatexReportBuilder(PlusReportBuilder):
    """
    Report builer for LaTeX format. Returns raw contents as string
    """

    def __init__(self, description_provider: VulnDescriptionProvider):
        """
        :param description_provider: A provider of vulnerability full description
        """
        self.description_provider = description_provider
        self.buffer = self.header
        self.colors = {SeverityLevels.High: 'FD6864',
                       SeverityLevels.Medium: 'F8A102',
                       SeverityLevels.Low: '34CDF9'}
        # these can be used at some point for adding color to cipher suites, currently ssl-cipher-enum
        # doesn't really seem to be matching with qualsys grading like they claim
        # for reference:
        # https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html
        # https://www.ssllabs.com/projects/rating-guide/
        # https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
        self.tls_colors = {TlS_Grade.FAIL: 'FD6864',
                           TlS_Grade.POOR: 'F8A102',
                           TlS_Grade.FAIR: 'f7f302',
                           TlS_Grade.GOOD: '4aef0e'
                           }

    def init_report(self, start_date: str, nmap_command: str):
        self._append('Flan Scan ran a network vulnerability scan with the following Nmap command on '
                     + start_date
                     + 'UTC.\n\\begin{lstlisting}\n'
                     + nmap_command
                     + '\n\\end{lstlisting}\nTo find out what IPs were scanned see the end of this report.\n')

    def build(self) -> Any:
        return self.buffer

    @property
    def header(self) -> str:
        return self.report_header

    def add_vulnerable_services(self, scan_results: Dict[str, ScanResult]):

        for s, report in scan_results.items():
            self._append('\\item \\textbf{\\large ' + s + ' \\large}')
            vulns = report.vulns
            locations = report.locations
            num_vulns = len(vulns)

            # adding a counting mechanism to minimize latex floats
            count = 0
            for v in vulns:
                count = count + 1
                description = self.description_provider.get_description(v.name, v.vuln_type)
                severity_name = v.severity_str
                self._append('\\begin{figure}[!htb]\n')
                self._append('\\begin{tabular}{|p{16cm}|}\\rowcolor[HTML]{'
                             + self.colors[severity_name]
                             + '} \\begin{tabular}{@{}p{15cm}>{\\raggedleft\\arraybackslash} p{0.5cm}@{}}\\textbf{'
                             + v.name + ' ' + severity_name + ' ('
                             + str(v.severity)
                             + ')} & \\href{' + description.url
                             + '}{\\large \\faicon{link}}'
                             + '\\end{tabular}\\\\\n Summary:'
                             + description.text
                             + '\\\\ \\hline \\end{tabular}  ')
                self._append('\\end{figure}\n')
                if count % 10 == 0:
                    self._append('\\clearpage\n')

            self._append('\\FloatBarrier\n\\textbf{The above '
                         + str(num_vulns)
                         + ' vulnerabilities apply to these network locations:}\n\\begin{itemize}\n')
            for addr in locations:
                self._append('\\item ' + addr + ' Ports: ' + str(locations[addr]) + '\n')
            self._append('\\\\ \\\\ \n \\end{itemize}\n')
        self._append('\\end{enumerate}\n')

    def add_non_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        for app_name, result in scan_results.items():
            self._append('\\item \\textbf{\\large ' + app_name + ' \\large}\n\\begin{itemize}\n')
            locations = result.locations
            for addr in locations:
                self._append('\\item ' + addr + ' Ports: ' + str(locations[addr]) + '\n')
            self._append('\\end{itemize}\n')
        self._append('\\end{enumerate}\n')

    def add_tls_versions(self, scan_results: Dict[str, TlsScanResult]):
        for s, report in scan_results.items():
            self._append('\\item \\textbf{\\large ' + s + ' \\large}')
            ciphers = report.ciphers

            for c in ciphers:
                self._append('\\begin{figure}[h!]\n')
                self._append('\\begin{tabular}{|p{16cm}|}\\begin{tabular}{@{}p{15cm}>{\\raggedleft\\arraybackslash} p{0.5cm}@{}}\\textbf{'
                             + c.name
                             + '}'
                             + '\\end{tabular}\\\\\n Key Exchange:'
                             + c.kex_info
                             + '\\\\ \\hline \\end{tabular}  ')
                self._append('\\end{figure}\n')
                self._append('\\FloatBarrier\n')

        self._append('\\end{enumerate}\n')

    def initialize_section(self):
        self._append('\\begin{enumerate}[wide, labelwidth=!, labelindent=0pt, label=\\textbf{\\large \\arabic{enumi} '
                     '\\large}]\n')

    def add_vulnerable_section(self):
        self._append('\\section*{Services with Vulnerabilities}')

    def add_non_vulnerable_section(self):
        self._append('\\section*{Services With No Known Vulnerabilities}')

    def add_tls_section(self):
        self._append('\\section*{TLS Versions}')

    def add_ips_section(self):
        self._append('\\section*{List of IPs Scanned}')
        self._append('\\begin{itemize}\n')

    def add_ip_address(self, ip: str):
        self._append('\\item ' + ip + '\n')

    def finalize(self):
        self._append('\\end{itemize}\n')
        self._append('\\end{document}')

    def _append(self, text: str):
        self.buffer += text

    # Don't want to depend on external file since this header is not so big.
    report_header = r"""\documentclass{article}
\usepackage{enumitem}
\usepackage[margin=1in]{geometry}
\usepackage[utf8]{inputenc}
\usepackage[table,xcdraw]{xcolor}
\usepackage{placeins}
\usepackage{hyperref}
\usepackage{fontawesome}
\usepackage{listings}
\lstset{
basicstyle=\small\ttfamily,
columns=flexible,
breaklines=true
}
\title{Flan Scan Report\\}
\date{\today}

\begin{document}

\maketitle

\section*{Summary}

"""
