import unittest
import ipaddress
import os
import logging
from configparser import ConfigParser

from vulnscan_parser.parser.nessus.xml import NessusParserXML
from vulnscan_parser.models.nessus.finding import NessusFinding
from vulnscan_parser.models.nessus.host import NessusHost
from vulnscan_parser.models.nessus.plugin import NessusPlugin
from vulnscan_parser.models.nessus.certificate import NessusCertificate
from vulnscan_parser.models.nessus.cipher import NessusCipher
from vulnscan_parser.models.nessus.service import NessusService

logging.basicConfig(level=logging.DEBUG)


class NessusParseNormalFile1TestCase(unittest.TestCase):

    HOST_NUM = 210
    HOST_PROPS = ('id', 'ip', 'hostnames', 'findings', 'plugins', 'services', 'src_file')

    FINDING_NUM = 4820
    FINDING_PROPS = ('id', 'host', 'plugin', 'src_file', 'svc_name', 'port', 'protocol', 'plugin_output',
                     'severity', 'risk_factor')

    PLUGIN_NUM = 134
    PLUGIN_PROPS = ('id', 'hosts', 'findings', 'pluginName', 'pluginFamily')

    parser = None
    file1 = ''

    @classmethod
    def setUpClass(cls):
        config_parser = ConfigParser()
        config_parser.read(os.path.join(os.path.dirname(__file__), 'config'))
        cls.file1 = os.path.expanduser(config_parser.get('nessus', 'file1'))
        cls.parser = NessusParserXML()
        cls._parse()

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
            self.assertIsInstance(host, NessusHost)
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
                self.assertIsInstance(finding, NessusFinding)
                self.assertIn(finding, self.parser.findings.values())
            for plugin in host.plugins:
                self.assertIsInstance(plugin, NessusPlugin)
                self.assertIn(plugin, self.parser.plugins.values())
            for service in host.services:
                self.assertIsInstance(service, NessusService)
                self.assertIn(service, self.parser.services.values())

    def test_findings(self):
        self.assertEqual(len(self.parser.findings), self.FINDING_NUM, 'Expected number of findings not matched')
        for finding_id, finding in self.parser.findings.items():
            self.assertIsInstance(finding, NessusFinding)
            actual_props = dir(finding)
            for prop in self.FINDING_PROPS:
                self.assertIn(prop, actual_props, 'Missing finding property {}'.format(prop))

            self.assertIsInstance(finding.host, NessusHost)
            self.assertIn(finding.host, self.parser.hosts.values())
            self.assertIsInstance(finding.plugin, NessusPlugin)
            self.assertIn(finding.plugin, self.parser.plugins.values())
            self.assertGreater(finding.port, -1)
            # TODO: check this
            self.assertIn(finding.protocol, ('TCP', 'UDP'))

    def test_plugins(self):
        self.assertEqual(len(self.parser.plugins), self.PLUGIN_NUM, 'Expected number of plugins not matched')
        for plugin_id, plugin in self.parser.plugins.items():
            self.assertIsInstance(plugin_id, int)
            self.assertIsInstance(plugin, NessusPlugin)
            actual_props = dir(plugin)
            for prop in self.PLUGIN_PROPS:
                self.assertIn(prop, actual_props, 'Missing plugin property {}'.format(prop))
            self.assertIsInstance(plugin.pluginID, int)
            self.assertGreater(plugin.pluginID, 0)
            self.assertGreater(len(plugin.pluginName), 0)

            for host in plugin.hosts:
                self.assertIsInstance(host, NessusHost)
                self.assertIn(host, self.parser.hosts.values())
            for finding in plugin.findings:
                self.assertIsInstance(finding, NessusFinding)
                self.assertIn(finding, self.parser.findings.values())

    def test_parse_again(self):
        findings = self.parser.findings
        plugins = self.parser.plugins
        hosts = self.parser.hosts
        certs = self.parser.certificates
        ciphers = self.parser.ciphers
        self._parse()
        self.assertEqual(self.parser.findings, findings)
        self.assertEqual(self.parser.plugins, plugins)
        self.assertEqual(self.parser.hosts, hosts)
        self.assertEqual(self.parser.certificates, certs)
        self.assertEqual(self.parser.ciphers, ciphers)
