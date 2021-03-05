import os
import sys
from typing import IO

from requests import Session

from contrib.descriptions import CveProjectProvider, VulnDescriptionProvider
from contrib.parsers import FlanPlusXmlParser, FlanXmlParser
from contrib.report_builders import ReportBuilder, LatexReportBuilder, MarkdownReportBuilder, JinjaHtmlReportBuilder, \
    JsonReportBuilder, PlusLatexReportBuilder, PlusReportBuilder


def create_report(parser: FlanXmlParser, builder: ReportBuilder, nmap_command: str, start_date: str, output_writer: IO,
                  ip_reader: IO):

    builder.init_report(start_date, nmap_command)

    if parser.vulnerable_services:
        builder.add_vulnerable_section()
        builder.initialize_section()
        builder.add_vulnerable_services(parser.vulnerable_dict)

    if parser.non_vuln_services:
        builder.add_non_vulnerable_section()
        builder.initialize_section()
        builder.add_non_vulnerable_services(parser.non_vulnerable_dict)

    builder.add_ips_section()
    for ip in ip_reader:
        builder.add_ip_address(ip.strip())

    builder.finalize()
    output_writer.write(builder.build())


def create_plus_report(parser: FlanPlusXmlParser, builder: PlusReportBuilder, nmap_command: str, start_date: str, output_writer: IO,
                  ip_reader: IO):

    builder.init_report(start_date, nmap_command)

    if parser.vulnerable_services:
        builder.add_vulnerable_section()
        builder.initialize_section()
        builder.add_vulnerable_services(parser.vulnerable_dict)

    if parser.non_vuln_services:
        builder.add_non_vulnerable_section()
        builder.initialize_section()
        builder.add_non_vulnerable_services(parser.non_vulnerable_dict)

    builder.add_tls_section()
    builder.initialize_section()
    builder.add_tls_versions(parser.tls_results)

    builder.add_ips_section()
    for ip in ip_reader:
        builder.add_ip_address(ip.strip())

    builder.finalize()
    output_writer.write(builder.build())


def parse_nmap_command(raw_command: str) -> str:
    nmap_split = raw_command.split()[:-1]  # remove last element, ip address
    nmap_split[3] = '<output-file>'
    return ' '.join(nmap_split)


def create_default_provider() -> VulnDescriptionProvider:
    return CveProjectProvider(Session())


def create_report_builder(report_type: str) -> ReportBuilder:
    builder_map = {
        'tex': lambda p: LatexReportBuilder(p),
        'tex-plus': lambda p: PlusLatexReportBuilder(p),
        'md': lambda p: MarkdownReportBuilder(p),
        'html': lambda p: JinjaHtmlReportBuilder(p),
        'json': lambda p: JsonReportBuilder(p)
    }

    if report_type not in builder_map:
        raise NotImplementedError(report_type)

    provider = create_default_provider()
    return builder_map[report_type](provider)


def create_plus_report_builder(report_type: str) -> PlusReportBuilder:
    builder_map = {

        # 'tex': lambda p: LatexReportBuilder(p),
        'tex-plus': lambda p: PlusLatexReportBuilder(p),
        # 'md': lambda p: MarkdownReportBuilder(p),
        # 'html': lambda p: JinjaHtmlReportBuilder(p),
        # 'json': lambda p: JsonReportBuilder(p)
    }

    if report_type not in builder_map:
        raise NotImplementedError(report_type)

    provider = create_default_provider()
    return builder_map[report_type](provider)


def main(dirname: str, output_file: str, ip_file: str, report_type: str = 'tex'):
    nmap_command = ''
    start_date = ''
    if '-plus' in report_type:
        builder = create_plus_report_builder(report_type)
        parser = FlanPlusXmlParser()
    else:
        builder = create_report_builder(report_type)
        parser = FlanXmlParser()

    for entry in os.scandir(dirname):  # type: os.DirEntry
        if not (entry.is_file() and entry.name.endswith('.xml')):
            continue
        data = parser.read_xml_file(entry.path)
        parser.parse(data)
        nmap_command = parse_nmap_command(data['nmaprun']['@args'])
        start_date = data['nmaprun']['@startstr']

    with open(output_file, 'w+') as output, open(ip_file) as ip_source:
        if '-plus' in report_type:
            create_plus_report(parser, builder, nmap_command, start_date, output, ip_source)
        else:
            create_report(parser, builder, nmap_command, start_date, output, ip_source)


if __name__ == '__main__':
    report_format = os.getenv('format', 'tex-plus')
    main(*sys.argv[1:4], report_type=report_format)
