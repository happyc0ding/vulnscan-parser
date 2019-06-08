import unittest
import ipaddress
import os
import logging
from configparser import ConfigParser

from vulnscan_parser.parser.testssl.json import TestsslParserJson
from vulnscan_parser.models.testssl.finding import TestsslFinding
from vulnscan_parser.models.testssl.host import TestsslHost
from vulnscan_parser.models.testssl.certificate import TestsslCertificate
from vulnscan_parser.models.testssl.cipher import TestsslCipher
from vulnscan_parser.models.testssl.service import TestsslService
from vulnscan_parser.models.testssl.vulnerability import TestsslVulnerability

logging.basicConfig(level=logging.DEBUG)


class TestsslParsePrettyFile1TestCase(unittest.TestCase):

    HOST_NUM = 1
    HOST_PROPS = ('id', 'ip', 'hostnames', 'findings', 'services', 'src_file')

    FINDING_NUM = 86
    FINDING_PROPS = ('id', 'host', 'vulnerability', 'hostname', 'src_file', 'port', 'protocol',
                     'finding', 'severity', 'name')

    VULN_NUM = 85
    VULN_PROPS = ('id', 'name', 'findings', 'cve', 'cwe')

    config_parser = None
    parser = None
    file1 = ''

    @classmethod
    def setUpClass(cls):
        cls.root_path = os.path.join(os.path.join(os.path.dirname(__file__)))
        cls.config_parser = ConfigParser()
        cls.config_parser.read(os.path.join(cls.root_path, 'config'))
        cls.parser = TestsslParserJson()
        cls._get_conf()
        cls._parse()

    @classmethod
    def _get_conf(cls):
        cls.file1 = os.path.join(cls.root_path, cls.config_parser.get('testssl', 'dir_pretty'), cls.config_parser.get('testssl', 'file1'))

    @classmethod
    def _parse(cls):
        print('---------------------------------- PARSE ----------------------------------------------------------')
        cls.parser.parse(cls.file1)

    def test_parsing_basics(self):
        self.assertGreater(len(self.parser.findings), 0, 'No findings after parsing')
        self.assertGreater(len(self.parser.hosts), 0, 'No hosts after parsing')
        self.assertGreater(len(self.parser.certificates), 0, 'No certs after parsing')
        self.assertGreater(len(self.parser.ciphers), 0, 'No ciphers after parsing')
        self.assertGreater(len(self.parser.services), 0, 'No services after parsing')

    def test_hosts(self):
        self.assertEqual(len(self.parser.hosts), self.HOST_NUM, 'Expected number of hosts not matched')
        for host_id, host in self.parser.hosts.items():
            self.assertIsInstance(host, TestsslHost)
            actual_props = dir(host)
            for prop in self.HOST_PROPS:
                self.assertIn(prop, actual_props, 'Missing host property {}'.format(prop))

            ipaddress.ip_address(host.ip)

            for hostname in host.hostnames:
                self.assertTrue('name' in hostname)
                self.assertTrue('type' in hostname)
                self.assertIsInstance(hostname['name'], str)
                self.assertGreater(len(hostname['name']), 0)

            for finding in host.findings:
                self.assertIsInstance(finding, TestsslFinding)
                self.assertIn(finding, self.parser.findings.values())
            for service in host.services:
                self.assertIsInstance(service, TestsslService)
                self.assertIn(service, self.parser.services.values())

    def test_findings(self):
        self.assertEqual(len(self.parser.findings), self.FINDING_NUM, 'Expected number of findings not matched')
        for finding_id, finding in self.parser.findings.items():
            self.assertIsInstance(finding, TestsslFinding)
            actual_props = dir(finding)
            for prop in self.FINDING_PROPS:
                self.assertIn(prop, actual_props, 'Missing finding property {}'.format(prop))

            self.assertIsInstance(finding.host, TestsslHost)
            self.assertIn(finding.host, self.parser.hosts.values())
            self.assertIsInstance(finding.vulnerability, TestsslVulnerability)
            self.assertGreater(finding.port, -1)
            self.assertEqual(finding.protocol, 'TCP')

    def test_vulnerabilities(self):
        self.assertEqual(len(self.parser.vulnerabilities), self.VULN_NUM, 'Expected number of vulns not matched')
        for plugin_id, vuln in self.parser.vulnerabilities.items():
            self.assertIsInstance(vuln, TestsslVulnerability)
            actual_props = dir(vuln)
            for prop in self.VULN_PROPS:
                self.assertIn(prop, actual_props, 'Missing vuln property {}'.format(prop))
            self.assertGreater(len(vuln.name), 0)

            for host in vuln.hosts:
                self.assertIsInstance(host, TestsslHost)
                self.assertIn(host, self.parser.hosts.values())
            for finding in vuln.findings:
                self.assertIsInstance(finding, TestsslFinding)
                self.assertIn(finding, self.parser.findings.values())

    def test_compare_pretty_normal(self):
        normal_parser = TestsslParserJson()
        normal_parser.parse(os.path.expanduser(self.config_parser.get('testssl', 'file1')))

        normal_vulns = normal_parser.vulnerabilities
        pretty_vulns = self.parser.vulnerabilities

        self.assertEqual(len(normal_parser.vulnerabilities), len(self.parser.vulnerabilities))
        for vuln_id in set(normal_vulns.keys()) | set(pretty_vulns.keys()):
            self.assertIn(vuln_id, normal_vulns)
            self.assertIn(vuln_id, pretty_vulns)
            self.assertEqual(normal_vulns[vuln_id].name, pretty_vulns[vuln_id].name)

            normal_findings = normal_vulns[vuln_id].findings
            pretty_findings = pretty_vulns[vuln_id].findings
            for finding in normal_findings | pretty_findings:
                self.assertIn(finding.name, (f.name for f in normal_parser.findings.values()))
                self.assertIn(finding.name, (f.name for f in self.parser.findings.values()))

        self.assertEqual(len(normal_parser.hosts), len(self.parser.hosts))
        normal_hosts = normal_parser.hosts
        pretty_hosts = self.parser.hosts
        for ip in set(normal_hosts.keys()) | set(pretty_hosts.keys()):
            self.assertIn(ip, normal_hosts)
            self.assertIn(ip, pretty_hosts)
            self.assertEqual(normal_hosts[ip].hostnames, pretty_hosts[ip].hostnames)

            normal_findings = normal_hosts[ip].findings
            pretty_findings = pretty_hosts[ip].findings
            for finding in normal_findings | pretty_findings:
                self.assertIn(finding.name, (f.name for f in normal_parser.findings.values()))
                self.assertIn(finding.name, (f.name for f in self.parser.findings.values()))

        self.assertEqual(len(normal_parser.findings), len(self.parser.findings))
        for finding in set(normal_parser.findings.values()) | set(self.parser.findings.values()):
            self.assertIn(finding.name, (f.name for f in normal_parser.findings.values()))
            self.assertIn(finding.name, (f.name for f in self.parser.findings.values()))
