import abc
from typing import Any, Dict

from contrib.internal_types import ScanResult, TlsScanResult
from .report_builder import ReportBuilder


__all__ = ['PlusReportBuilder']


class PlusReportBuilder(ReportBuilder):
    def init_report(self, start_date: str, nmap_command: str):
        """
        Creates document section with report overview
        """
        pass

    def build(self) -> Any:
        """
        :return: Ready report in specific format
        """
        pass

    def add_vulnerable_section(self):
        """
        Adds header for section with vulnerable services
        """
        pass

    def add_non_vulnerable_section(self):
        """
        Adds header for section with services without detected vulnerabilities
        """
        pass

    def add_tls_section(self):
        """
        Adds header for section with tls versions
        """
        pass

    def add_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        """
        Adds descriptions of vulnerable services
        """
        pass

    def add_non_vulnerable_services(self, scan_results: Dict[str, ScanResult]):
        """
        Adds descriptions of services without detected vulnerabilities
        """
        pass

    def add_tls_versions(self, scan_results: Dict[str, TlsScanResult]):
        """
        adds descriptions of tls versions
        :param scan_results:
        :return:
        """
        pass

    def initialize_section(self):
        """
        Adds begin of report section
        """
        pass

    def add_ips_section(self):
        """
        Adds section with list of scanned ip addresses
        """
        pass

    def add_ip_address(self, ip: str):
        """
        Adds IP-address to scanned addresses section
        """
        pass

    def finalize(self):
        """
        Adds report footer
        """
        pass
