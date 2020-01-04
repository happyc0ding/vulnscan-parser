import unittest
import ipaddress
import os
import logging
from configparser import ConfigParser, NoOptionError

from vulnscan_parser.parser.testssl.json import TestsslParserJson
from vulnscan_parser.models.testssl.finding import TestsslFinding
from vulnscan_parser.models.testssl.host import TestsslHost
from vulnscan_parser.models.testssl.certificate import TestsslCertificate
from vulnscan_parser.models.testssl.cipher import TestsslCipher
from vulnscan_parser.models.testssl.service import TestsslService
from vulnscan_parser.models.testssl.vulnerability import TestsslVulnerability

logging.basicConfig(level=logging.DEBUG)


class TestsslParseNormalAllTestCase(unittest.TestCase):

    HOST_PROPS = ('id', 'ip', 'hostnames', 'findings', 'services', 'src_file')

    FINDING_PROPS = ('id', 'host', 'vulnerability', 'hostname', 'src_file', 'port', 'protocol',
                     'finding', 'severity')

    VULN_PROPS = ('id', 'name', 'findings', 'cve', 'cwe')

    config_parser = None
    all_parsers = {}
    parser = None
    testssl_files = set()
    handled_files = set()
    current_file = ''

    @classmethod
    def setUpClass(cls):
        cls.config_parser = ConfigParser()
        cls.config_parser.read(os.path.join(os.path.dirname(__file__), 'config'))
        #cls.parser = TestsslParserJson()

        testssl_dir = cls.config_parser.get('testssl', 'dir_normal')
        test_files_path = os.path.join(os.path.dirname(__file__), testssl_dir)
        for test_file in os.listdir(test_files_path):
            file_path = os.path.join(testssl_dir, test_file)
            full_path = os.path.join(test_files_path, test_file)
            if file_path in cls.config_parser.sections():
                print('Found test file {}'.format(test_file))
                cls.testssl_files.add(file_path)
                parser = TestsslParserJson()
                parser.parse(full_path)
                cls.all_parsers[file_path] = parser
            else:
                print('Skipping check, no config for file {}'.format(test_file))

    def test_parsing_basics(self):
        for test_file in self.testssl_files:
            parser = self.all_parsers[test_file]
            self.assertGreater(len(parser.findings), 0, 'No findings after parsing')
            self.assertGreater(len(parser.hosts), 0, 'No hosts after parsing')
            self.assertGreater(len(parser.certificates), 0, 'No certs after parsing')
            self.assertGreater(len(parser.ciphers), 0, 'No ciphers after parsing')
            self.assertGreater(len(parser.services), 0, 'No services after parsing')

    def test_hosts(self):
        for test_file in self.testssl_files:
            parser = self.all_parsers[test_file]
            host_num = int(self.config_parser.get(test_file, 'host_num'))
            
            self.assertEqual(len(parser.hosts), host_num, 'Expected number of hosts not matched')
            for host_id, host in parser.hosts.items():
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
                    self.assertIn(finding, parser.findings.values())
                for service in host.services:
                    self.assertIsInstance(service, TestsslService)
                    self.assertIn(service, parser.services.values())

    def test_findings(self):
        for test_file in self.testssl_files:
            parser = self.all_parsers[test_file]
            finding_num = int(self.config_parser.get(test_file, 'finding_num'))
            self.assertEqual(len(parser.findings), finding_num, 'Expected number of findings not matched')
            for finding_id, finding in parser.findings.items():
                self.assertIsInstance(finding, TestsslFinding)
                actual_props = dir(finding)
                for prop in self.FINDING_PROPS:
                    self.assertIn(prop, actual_props, 'Missing finding property {}'.format(prop))

                self.assertIsInstance(finding.host, TestsslHost)
                self.assertIn(finding.host, parser.hosts.values())
                self.assertIsInstance(finding.vulnerability, TestsslVulnerability)
                self.assertGreater(finding.port, -1)
                self.assertEqual(finding.protocol, 'TCP')

    def test_vulnerabilities(self):
        for test_file in self.testssl_files:
            parser = self.all_parsers[test_file]
            vuln_num = int(self.config_parser.get(test_file, 'vuln_num'))
            self.assertEqual(len(parser.vulnerabilities), vuln_num, 'Expected number of vulns not matched')
            for plugin_id, vuln in parser.vulnerabilities.items():
                self.assertIsInstance(vuln, TestsslVulnerability)
                actual_props = dir(vuln)
                for prop in self.VULN_PROPS:
                    self.assertIn(prop, actual_props, 'Missing vuln property {}'.format(prop))
                self.assertGreater(len(vuln.name), 0)

                for host in vuln.hosts:
                    self.assertIsInstance(host, TestsslHost)
                    self.assertIn(host, parser.hosts.values())
                for finding in vuln.findings:
                    self.assertIsInstance(finding, TestsslFinding)
                    self.assertIn(finding, parser.findings.values())
