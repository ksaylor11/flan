from collections import defaultdict
from typing import Dict, Any, List, Set

import xmltodict

from contrib.internal_types import TlsScanResult, Vuln, Cipher, ScanResult
from .flan_xml_parser import FlanXmlParser


__all__ = ['FlanPlusXmlParser']


class FlanPlusXmlParser(FlanXmlParser):
    """
    NMAP XML file reader and contents parser
    """
    def __init__(self):
        super().__init__()
        self.results = defaultdict(ScanResult)
        self.vulnerable_services = []  # type: List[str]
        self.tls_results = defaultdict(TlsScanResult)
        self.tls_versions = []  # type: List[str]

    @property
    def vulnerable_dict(self) -> Dict[str, ScanResult]:
        """
        :return: Map {app_name -> scan result} for vulnerable services
        """
        return {service: self.results[service] for service in self.vulnerable_services}

    @property
    def non_vulnerable_dict(self) -> Dict[str, ScanResult]:
        """
        :return: Map {app_name -> scan result} for services without detected vulnerabilities
        """
        return {service: self.results[service] for service in self.non_vuln_services}

    @property
    def non_vuln_services(self) -> Set[str]:
        """
        :return: App names for services without detected vulnerabilities
        """
        return set(self.results) - set(self.vulnerable_services)

    @property
    def tls_dict(self) -> Dict[str, ScanResult]:
        """
        :return: tls versions with cipher suites
        """
        return {version: self.tls_results[version] for version in self.tls_versions}

    def parse(self, data: Dict[str, Any]):
        """
        Parse xmltodict output and fill internal collections
        :param data: xmltodict output
        """
        if 'host' not in data['nmaprun']:
            return

        hosts = data['nmaprun']['host']

        if isinstance(hosts, list):
            for h in hosts:
                self.parse_host(h)
        else:
            self.parse_host(hosts)

    def parse_vuln(self, app_name: str, vuln: List[Dict[str, Any]]):
        vuln_name = ''
        severity = ''
        vuln_type = ''
        for field in vuln:
            if field['@key'] == 'cvss':
                severity = float(field['#text'])
            elif field['@key'] == 'id':
                vuln_name = field['#text']
            elif field['@key'] == 'type':
                vuln_type = field['#text']

        self.results[app_name].vulns.append(Vuln(vuln_name, vuln_type, severity))

    def parse_ciphers(self, tls_version: str, ciphers: Dict[str, Any]):
        if 'table' not in ciphers:
            print('ERROR in script: ' + ciphers['@key'] +" tls: " + tls_version)
            return

        cipher_table = ciphers['table']
        for c in cipher_table:
            cipher_name = ''
            key_exchange = ''
            strength = ''
            for e in c['elem']:
                if e['@key'] == 'name':
                    cipher_name = e['#text']
                elif e['@key'] == 'kex_info':
                    key_exchange = e['#text']
                elif e['@key'] == 'strength':
                    strength = e['#text']
            self.tls_results[tls_version].ciphers.append(Cipher(cipher_name, key_exchange, strength))

    def parse_tls_version(self, app_name: str, table: Dict[str, Any]):
        if 'table' not in table:
            print('ERROR in script: ' + table['@key'] +" app: " + app_name)
            return
        tls_version = table['@key']
        self.tls_versions.append(tls_version)
        cipher_table = table['table']
        if isinstance(cipher_table, list):
            for cipher in cipher_table:
                if cipher['@key'] == 'ciphers':
                    self.parse_ciphers(tls_version, cipher)
        else:
            if cipher_table['@key'] == 'ciphers':
                self.parse_ciphers(tls_version, cipher_table)

    def parse_script(self, ip_addr: str, port: str, app_name: str, script: Dict[str, Any]):
        if 'table' not in script:
            print('ERROR in script: ' + script['@output'] + " at location: " + ip_addr + " port: " + port + " app: " +
                  app_name)
            return
        self.vulnerable_services.append(app_name)
        script_table = script['table']['table']
        if isinstance(script_table, list):
            for vuln in script_table:
                self.parse_vuln(app_name, vuln['elem'])
        else:
            self.parse_vuln(app_name, script_table['elem'])

    def parse_tls_script(self, ip_addr: str, port: str, app_name: str, script: Dict[str, Any]):
        if 'table' not in script:
            print('ERROR in script: ' + script['@output'] + " at location: " + ip_addr + " port: " + port + " app: " +
                  app_name)
            return
        tls_table = script['table']
        if isinstance(tls_table, list):
            for tls_version in tls_table:
                self.parse_tls_version(app_name, tls_version)
        else:
            self.parse_tls_version(app_name, tls_table)

    def parse_port(self, ip_addr: str, port: Dict[str, Any]):
        if port['state']['@state'] == 'closed':
            return

        app_name = self.get_app_name(port['service'])
        port_num = port['@portid']
        new_app = app_name not in self.results
        self.results[app_name].locations[ip_addr].append(port_num)

        if new_app and 'script' in port:  # vulnerabilities parsed only if this app didn't appear before
            scripts = port['script']
            if isinstance(scripts, list):
                for s in scripts:
                    if s['@id'] == 'vulners':
                        self.parse_script(ip_addr, port_num, app_name, s)
                    elif s['@id'] == 'ssl-enum-ciphers':
                        self.parse_tls_script(ip_addr, port_num, app_name, s)
            else:
                if scripts['@id'] == 'vulners':
                    self.parse_script(ip_addr, port_num, app_name, scripts)
                elif scripts['@id'] == 'ssl-enum-ciphers':
                    self.parse_tls_script(ip_addr, port_num, app_name, scripts)

    def parse_host(self, host: Dict[str, Any]):
        addresses = host['address']
        ip_addr = ''
        if isinstance(addresses, list):
            for addr in addresses:
                if "ip" in addr['@addrtype']:
                    ip_addr = addr['@addr']
        else:
            ip_addr = addresses['@addr']

        if not ip_addr:
            return

        if host['status']['@state'] == 'up' and 'ports' in host.keys() and 'port' in host['ports']:
            ports = host['ports']['port']
            if isinstance(ports, list):
                for p in ports:
                    self.parse_port(ip_addr, p)
            else:
                self.parse_port(ip_addr, ports)

    def read_xml_file(self, path: str) -> Dict[str, Any]:
        """
        Read file and convert to dictionary. To read raw contents use `read_xml_contents`

        :param path: path to .xml file
        :return: parsed contents
        """
        with open(path) as f:
            contents = f.read()
            return self.read_xml_contents(contents)

    @staticmethod
    def get_app_name(service: Dict[str, Any]) -> str:
        app_name = ''
        if '@product' in service:
            app_name += service['@product'] + ' '
            if '@version' in service:
                app_name += service['@version'] + ' '
        elif '@name' in service:
            app_name += service['@name'] + ' '

        if 'cpe' in service:
            if isinstance(service['cpe'], list):
                for cpe in service['cpe']:
                    app_name += '(' + cpe + ') '
            else:
                app_name += '(' + service['cpe'] + ') '
        return app_name

    @staticmethod
    def read_xml_contents(contents: str) -> Dict[str, Any]:
        return xmltodict.parse(contents)
