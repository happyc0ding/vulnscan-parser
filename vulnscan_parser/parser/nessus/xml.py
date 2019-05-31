import logging

# try lxml, but use built-in as fallback
try:
    from lxml import etree as elmtree
except ImportError:
    from xml.etree import ElementTree as elmtree
import os
from datetime import datetime, timezone
import ipaddress
from itertools import islice

from pyparsing import CharsNotIn, LineEnd, Word, ZeroOrMore, delimitedList, alphanums

from vulnscan_parser.parser.base import VSBaseParser
from vulnscan_parser.models.nessus.finding import NessusFinding
from vulnscan_parser.models.nessus.host import NessusHost
from vulnscan_parser.models.nessus.plugin import NessusPlugin
from vulnscan_parser.models.nessus.certificate import NessusCertificate
from vulnscan_parser.models.nessus.cipher import NessusCipher
from vulnscan_parser.models.nessus.service import NessusService

LOGGER = logging.getLogger(__name__)


class NessusParserXML(VSBaseParser):

    # 10863 SSL VSCertificate Information
    PLUGIN_ID_CERT_INFO = 10863
    # 21643 SSL Cipher Suites Supported
    PLUGIN_ID_CIPHER_INFO = 21643
    # 46180 Additional DNS Hostnames
    PLUGIN_ID_ADDITIONAL_HOSTNAMES = 46180
    # 12053 Host Fully Qualified Domain Name (FQDN) Resolution
    PLUGIN_ID_FQDN = 12053
    # 22964 Service Detection
    PLUGIN_ID_SERVICE_DETECTION = 22964

    CERT_DATE_PATTERN_DFLT = '%b %d %H:%M:%S %Y %Z'

    # some date properties need special handling
    DATE_PROPERTIES = {
        'HOST_START',
        'HOST_END'
    }

    # some tags are mapped to other names, because the xml data structure would not make any sense
    HOST_TAG_MAP_DFLT = {
        'ReportHost': {
            'host-ip': 'ip',
            'HOST_START': 'host_start',
            'HOST_END': 'host_end',
        },
    }

    # these attributes are mapped to findings instead of plugins
    # TODO: run more tests -> are other values dynamic?
    FINDING_PROPERTIES = {
        'svc_name',
        'port',
        'protocol',
        'plugin_output',
        'freebsd',
    }

    # these will be set for the plugin and the finding
    FINDING_PLUGIN_PROPERTIES = {
        'risk_factor',
        'severity',
    }

    # the following properties exist more than once in the xml and have to be mapped to a set or similar
    # nessus..., oh my...
    PROPERTY_TO_LIST_MAP = {
        'osvdb',
        'secunia',
        'xref',
        'bid',
        'cve',
        'cwe'
    }

    # this information will be ignored by default
    PLUGIN_PROPERTIES_BLACKLIST_DFLT = {
        # pluginID is set manually
        'pluginID',
        'synopsis',
        'plugin_modification_date',
        'script_version',
        'solution',
        'plugin_modification_date',
        'plugin_name',
        'plugin_publication_date',
        # 'plugin_type',
        'agent',
        'see_also',
        'fname',
        'cpe',
        'attachment',
        'canvas_package'
    }

    # these attributes will be ignored by default
    HOST_PROPERTIES_BLACKLIST_DFLT = {
        'id'
    }

    def __init__(self):
        super().__init__()
        # blacklist for plugin attributes/data. change this, if needed
        self.plugin_attributes_blacklist = self.PLUGIN_PROPERTIES_BLACKLIST_DFLT.copy()
        # will be changed when parsing starts! list of properties and attributes to ignore
        self._merged_plugin_tags_attributes_blacklist = set()
        # blacklist for host attributes/data. change this, if needed
        self.host_attr_blacklist = self.HOST_PROPERTIES_BLACKLIST_DFLT.copy()
        # some tags are mapped to other names, because the xml data structure would not make any sense
        self.host_tag_map = self.HOST_TAG_MAP_DFLT.copy()
        # additional switch to turn logging of parsing details on or off
        self.log = False
        # all parsed plugins
        self._plugins = {}
        # all parsed hosts
        self._hosts = {}
        # all parsed findings
        self._findings = {}
        # all parsed certificates
        self._certificates = {}
        # all parsed ciphers
        self._ciphers = {}
        # all parsed services
        self._services = {}
        # iterparse will set this flag to False in order to save memory
        self._save_result_lists = True
        # set finding attrs/props
        self._finding_properties = self.FINDING_PROPERTIES | self.FINDING_PLUGIN_PROPERTIES

    def get_results(self):
        return self.plugins, self.hosts, self.findings, self.services, self.certificates, self.ciphers

    @property
    def hosts(self):
        return self._hosts.copy()

    @property
    def plugins(self):
        return self._plugins.copy()

    @property
    def findings(self):
        return self._findings.copy()

    @property
    def certificates(self):
        return self._certificates.copy()

    @property
    def ciphers(self):
        return self._ciphers.copy()

    @property
    def services(self):
        return self._services.copy()

    def clear(self):
        self._curr_filename = ''
        self._services.clear()
        self._certificates.clear()
        self._ciphers.clear()
        self._findings.clear()
        self._plugins.clear()
        self._hosts.clear()

    def parse(self, filepath):
        LOGGER.info('Parsing file {}'.format(filepath))
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)
        self._merged_plugin_tags_attributes_blacklist = self.FINDING_PROPERTIES | self.plugin_attributes_blacklist

        # init vars
        host = None
        host_name_attr = ''
        # noinspection PyBroadException
        try:
            for event, element in elmtree.iterparse(
                    filepath, events=('start', 'end'), tag=('ReportHost', 'ReportItem', 'HostProperties')):
                if 'start' == event:
                    if self.log:
                        LOGGER.debug('Got element "{elm}" with attrs "{attrs}"'.format(
                            elm=element.tag, attrs=element.attrib))
                    if 'ReportHost' == element.tag:
                        # get name attribute
                        host = None
                        host_name_attr = element.attrib['name']
                elif 'end' == event:
                    if self.log:
                        LOGGER.debug('Finished element "{elm}"'.format(elm=element.tag))
                    if 'HostProperties' == element.tag:
                        host = self.handle_host(element, host_name_attr)
                    elif 'ReportItem' == element.tag:
                        plugin = self.handle_plugin(element, host)
                        self.handle_finding(element, host, plugin)
                    elif 'ReportHost' == element.tag:
                        self._parse_add_hostnames(host)
                        self._parse_add_services(host)
                    # # iterative parsing: yield after every host
                    # elif parse_hosts_iterative and 'ReportHost' == element.tag:
                    #     plugin_dict = {plugin.pluginID: plugin for plugin in host.plugins}
                    #     yield host, self._get_certs(plugin_dict), self._get_ciphers(plugin_dict)
                    element.clear()
            self._get_certs(self._plugins)
            self._get_ciphers(self._plugins)
        except Exception:
            LOGGER.exception('Error while parsing {}'.format(filepath))

    def handle_finding(self, plugin_elm, host, plugin):
        # map to finding, since a plugin may match multiple ports per host
        finding = NessusFinding()
        # set host
        finding.host = host
        # set plugin
        finding.plugin = plugin
        # set file name
        finding.src_file = self._curr_filename
        # set other attributes
        for f_key in self._finding_properties:
            find_val = None
            try:
                # try to get from element attributes
                find_val = plugin_elm.attrib[f_key]
            except KeyError:
                plugin_elm_child = plugin_elm.find('./{}'.format(f_key))
                if plugin_elm_child is not None:
                    find_val = plugin_elm_child.text
            if find_val is not None:
                if 'port' == f_key:
                    # fix format for port
                    find_val = int(find_val)
                elif 'protocol' == f_key:
                    find_val = find_val.upper()
                setattr(finding, f_key, find_val)

        # WTF tenable, service detection may occurr multiple times -> hash plugin output
        finding.id = '-'.join(map(str, (finding.host.ip, finding.plugin.pluginID, finding.port,
                                        finding.protocol, self.hash_sha1(finding.plugin_output.encode()))))

        # add service from finding info
        self._add_service(finding)

        save_host_plugin = True
        if self._save_result_lists:
            save_host_plugin = self._save_to_result_dict(self._findings, finding)

        if save_host_plugin:
            # add finding to host
            host.findings.add(finding)
            # add finding to plugin
            plugin.findings.add(finding)

    def handle_plugin(self, plugin_elm, host):
        plugin_id = int(plugin_elm.attrib['pluginID'])
        try:
            plugin = self._plugins[plugin_id]
        except KeyError:
            plugin = NessusPlugin()
            plugin.id = plugin_id
            plugin.pluginID = plugin_id
            # get other attrs except data for finding and blacklist
            for attr_k, attr_v in plugin_elm.attrib.items():
                if attr_k not in self._merged_plugin_tags_attributes_blacklist:
                    setattr(plugin, attr_k, attr_v)

            for plugin_elm_child in plugin_elm.iterchildren():
                pe_key = plugin_elm_child.tag
                pe_value = plugin_elm_child.text
                if pe_key not in self._merged_plugin_tags_attributes_blacklist:
                    if pe_key in self.PROPERTY_TO_LIST_MAP:
                        pe_value = [pe_value]
                    setattr(plugin, pe_key, pe_value)

            if self._save_result_lists:
                # save plugin in list (plugins should always be the same)
                self._plugins[plugin.pluginID] = plugin

        # add host to plugin
        plugin.hosts.add(host)
        # add plugin to host
        host.plugins.add(plugin)

        #LOGGER.debug('handled plugin {} {} with host {}'.format(plugin.pluginID, plugin, host))

        return plugin

    def handle_host(self, host_prop_elm, host_name_attr):
        host = NessusHost()
        host.name = host_name_attr
        # name may be a hostname or an ip address
        try:
            ipaddress.ip_address(host.name)
            host.ip = host.name
        except ValueError:
            host.add_hostname(host.name, 'user')

        for host_prop_tag in host_prop_elm.iterchildren():
            # i.e. <tag name="host-ip">10.64.3.136</tag>
            host_prop_name = host_prop_tag.attrib['name']
            host_prop_value = host_prop_tag.text
            # replace double spaces in date fields, since nessus uses the following formats
            # Tue Nov 21 18:00:00 2017
            # Tue Nov  1 18:00:00 2017
            # -> note the added space for day of month in the 2nd case which causes problems with parsing in other
            # tools when you have to specify a fixed date pattern for parsing
            if host_prop_name in self.DATE_PROPERTIES:
                # remove double spaces
                host_prop_value = host_prop_value.replace('  ', ' ')
                host_prop_value = datetime.strptime(host_prop_value, '%a %b %d %H:%M:%S %Y')

            # set other attributes, also overwrite previously read 'name' attribute with 'host-ip' tag
            try:
                host_prop_name = self.host_tag_map['ReportHost'][host_prop_name]
            except KeyError:
                pass
            # properties/attrs must not contain "-"
            host_prop_name = host_prop_name.replace('-', '_')

            # ip is a special case since it is usually set by the name attribute of the ReportHost tag
            # however, this might be a hostname instead of an ip -> ips are stored in host-ip of a name tag
            # however, unfinished scans might be missing the "host-ip" name tag...
            if 'ip' == host_prop_name:
                try:
                    ipaddress.ip_address(host_prop_value)
                    setattr(host, host_prop_name, host_prop_value)
                except ValueError:
                    pass
            # set attribute
            setattr(host, host_prop_name, host_prop_value)

        # host id is the ip address
        host.id = host.ip
        try:
            known_host = self._hosts[host.ip]
            LOGGER.info('IP already in results: {} (first entry has priority). Merging findings '
                        '(and plugins, hostnames, services) only'.format(known_host.ip))
            # merge hostnames
            for hn in host.hostnames:
                known_host.add_hostname_dict(hn)

            # use already known host
            host = known_host
        except KeyError:
            if self._save_result_lists:
                self._hosts[host.ip] = host

        try:
            host.add_hostname(host.host_fqdn, 'PTR')
        except AttributeError:
            pass
        # add src file
        host.src_file.add(self._curr_filename)
        # add hostnames
        #self._parse_add_hostnames(host)
        # add services
        # TODO: only simple service detection for now
        #self._parse_add_services(host)

        #LOGGER.debug('handled host {} with {}'.format(host.ip, host))

        return host

    def _parse_add_hostnames(self, host):
        hostnames = set()
        for finding in host.findings:
            if self.PLUGIN_ID_ADDITIONAL_HOSTNAMES == finding.plugin.pluginID:
                hostnames |= self._parse_fqdn(finding)

            elif self.PLUGIN_ID_FQDN == finding.plugin.pluginID:
                hostnames |= set(self._parse_hostname(finding))
        for hn in hostnames:
            if hn and hn != host.name:
                host.add_hostname(hn, 'PTR')

    # TODO: improve code
    def _parse_cert(self, finding):
        cert = NessusCertificate()
        cert.finding = finding
        is_san = False
        is_subject = False
        is_issuer = False
        is_sha2fp = False

        # noinspection PyBroadException
        try:
            separator = '\n'
            # WTF Tenable?
            if finding.plugin_output.startswith('Subject Name: \\n\\n'):
                separator = '\\n'
            for line in finding.plugin_output.split(separator):
                if line.startswith('Subject Name:'):
                    is_subject = True
                elif line.startswith('Issuer Name:'):
                    is_subject = False
                    is_issuer = True
                elif self._setattr_by_condition_str(line, 'Not Valid Before: ', cert, 'not_before'):
                    cert.not_before = datetime.strptime(cert.not_before, self.CERT_DATE_PATTERN_DFLT)
                elif self._setattr_by_condition_str(line, 'Not Valid After: ', cert, 'not_after'):
                    cert.not_after = datetime.strptime(cert.not_after, self.CERT_DATE_PATTERN_DFLT)
                elif line.startswith('Key Length: '):
                    cert.public_key_len = int(line[len('Key Length: '):].split(' ')[0])
                elif line.startswith('Serial Number: '):
                    is_issuer = False
                    cert.serial_number = line[len('Serial Number: '):].replace(' ', '')
                elif is_subject:
                    self._setattr_by_condition_str(line, 'Common Name: ', cert, 'subject["CN"]')
                    self._setattr_by_condition_str(line, 'Country: ', cert, 'subject["C"]')
                    self._setattr_by_condition_str(line, 'State/Province: ', cert, 'subject["ST"]')
                    self._setattr_by_condition_str(line, 'Locality: ', cert, 'subject["L"]')
                    self._setattr_by_condition_str(line, 'Organization: ', cert, 'subject["O"]')
                    self._setattr_by_condition_str(line, 'Organization Unit: ', cert, 'subject["OU"]')
                elif is_issuer:
                    self._setattr_by_condition_str(line, 'Common Name: ', cert, 'issuer["CN"]')
                    self._setattr_by_condition_str(line, 'Country: ', cert, 'issuer["C"]')
                    self._setattr_by_condition_str(line, 'State/Province: ', cert, 'issuer["ST"]')
                    self._setattr_by_condition_str(line, 'Locality: ', cert, 'issuer["L"]')
                    self._setattr_by_condition_str(line, 'Organization: ', cert, 'issuer["O"]')
                    self._setattr_by_condition_str(line, 'Organization Unit: ', cert, 'issuer["OU"]')
                elif self._setattr_by_condition_str(line, 'SHA-256 Fingerprint: ', cert, 'sha2_fingerprint'):
                    is_sha2fp = True
                elif is_sha2fp:
                    cert.sha2_fingerprint += line.strip('')
                    is_sha2fp = False
                elif line.startswith('Extension: '):
                    is_san = False
                    if line.startswith('Extension: Subject Alternative Name'):
                        is_san = True
                elif is_san and line.startswith('DNS: '):
                    cert.san.append(line[len('DNS: '):])
                else:
                    self._setattr_by_condition_str(line, 'SHA-1 Fingerprint: ', cert, 'sha2_fingerprint')
                    self._setattr_by_condition_str(line, 'Signature Algorithm: ', cert, 'signature_algorithm')

                # replace spaces
                cert.sha1_fingerprint = cert.sha1_fingerprint.replace(' ', '')
                cert.sha2_fingerprint = cert.sha2_fingerprint.replace(' ', '')

                cert.id = '{}-{}-{}-{}'.format(cert.sha2_fingerprint, cert.finding.host.ip,
                                               cert.finding.protocol, cert.finding.port)
                cert.src_file = self._curr_filename
        except Exception:
            LOGGER.exception('Error while parsing cert')

        return cert

    def _setattr_by_condition_str(self, line, cond_str, obj, attr):
        if line.startswith(cond_str):
            setattr(obj, attr, line[len(cond_str):])
            return True

        return False

    def _get_certs(self, plugins):
        certs = {}
        # check if plugin exists
        try:
            plugins[self.PLUGIN_ID_CERT_INFO]
        except KeyError:
            return {}

        for finding in plugins[self.PLUGIN_ID_CERT_INFO].findings:
            cert = self._parse_cert(finding)
            certs[cert.id] = cert
            if self._save_result_lists:
                self._save_to_result_dict(self._certificates, cert)

        return certs

    def _get_ciphers(self, plugins):
        ciphers = {}
        # check if plugin exists
        try:
            plugins[self.PLUGIN_ID_CIPHER_INFO]
        except KeyError:
            return {}

        for finding in plugins[self.PLUGIN_ID_CIPHER_INFO].findings:
            for cipher in self._parse_ciphers(finding):
                ciphers[cipher.id] = cipher
                if self._save_result_lists:
                    self._save_to_result_dict(self._ciphers, cipher)

        return ciphers

    def _parse_hostname(self, finding):
        hostnames = set()
        for line in finding.plugin_output.split('\n'):
            line = line.strip()
            start_index = line.find('- ')
            if start_index > -1:
                hostname = line[start_index + 2:]
                hostnames.add(hostname)

        return hostnames

    def _parse_fqdn(self, finding):
        hostnames = set()
        for line in finding.plugin_output.split('\n'):
            start_index = line.find('resolves as ')
            if start_index > -1:
                hostnames.add(line[start_index + len('resolves as '):].strip(' .'))

        return hostnames

    def _parse_ciphers(self, finding):
        ciphers = []
        lines = finding.plugin_output.split('\n')

        read_ciphers = False
        curr_proto = None

        space_chars = ' \t'
        word = CharsNotIn(space_chars)
        space = Word(space_chars, exact=1)
        cipher_name = delimitedList(word, delim=space, combine=True)
        # an alternative construction for 'name' could be:
        # label = Combine(word + ZeroOrMore(space + word))
        value = Word(alphanums + '-_()=/')
        line_expr = cipher_name('name') + value('kx') + value('au') + value('enc') + value('mac') + \
            ZeroOrMore(value('export')) + LineEnd().suppress()

        # noinspection PyBroadException
        try:
            for line in lines:
                if read_ciphers and line.startswith('    '):
                    line_res = line_expr.parseString(line.lstrip(' '))

                    cipher = NessusCipher()
                    cipher.host = finding.host
                    cipher.port = finding.port
                    cipher.protocol = finding.protocol
                    cipher.hostname = finding.hostname
                    cipher.src_file = finding.src_file
                    cipher.name = line_res.name
                    # key size may be "None". Sample:
                    # ['TLS-NULL-NULL-NULL', 'Kx=None', 'Au=None', 'Enc=None', 'Mac=None']
                    if 'Enc=None' == line_res.enc:
                        cipher.key_size = 0
                    else:
                        cipher.key_size = int(line_res.enc.partition('(')[-1].rpartition(')')[0])
                    cipher.tls_protocol = curr_proto

                    # fix naming
                    if 'SSLv2' == cipher.tls_protocol:
                        cipher.tls_protocol = 'SSLv2'
                    elif 'SSLv3' == cipher.tls_protocol:
                        cipher.tls_protocol = 'SSLv3'
                    elif 'TLSv1' == cipher.tls_protocol:
                        cipher.tls_protocol = 'TLSv1.0'
                    elif 'TLSv11' == cipher.tls_protocol:
                        cipher.tls_protocol = 'TLSv1.1'
                    elif 'TLSv12' == cipher.tls_protocol:
                        cipher.tls_protocol = 'TLSv1.2'

                    cipher.id = '{name}-{tls_proto}-{ip}-{proto}-{port}'.format(
                        name=cipher.name, tls_proto=cipher.tls_protocol, ip=cipher.host.ip,
                        proto=cipher.protocol, port=cipher.port)

                    ciphers.append(cipher)

                if line.startswith('SSL Version : '):
                    curr_proto = line.split(':')[1].strip(' ')
                    read_ciphers = True
                elif line.strip(' ').startswith('Unrecognized Ciphers'):
                    read_ciphers = False

        except Exception:
            LOGGER.exception('Error while parsing ciphers')

        return ciphers

    # def normalize_base_sw_name(self, name):
    #     # TODO: does normalizing make sense here?
    #     name_map = {
    #         'apache httpd': 'Apache',
    #         'apache': 'Apache',
    #         'tomcat': 'Apache Tomcat',
    #         'coyote': 'Apache Tomcat/Coyote',
    #         'openssh': 'OpenSSH',
    #         'bigip': 'BIG-IP',
    #         'big-ip': 'BIG-IP',
    #     }
    #     for map_name, new_name in name_map.items():
    #         if map_name == name.lower():
    #             return new_name
    #
    #     return name
    #     #
    #     # # fix different naming "Debian-" vs "Debian "
    #     # # this is gonna suck since there will be more products
    #     # elif ' Debian-' in service.base_software_version:
    #     #     service.base_software_version = service.base_software_version.replace(' Debian-', ' Debian ')

    def _add_service(self, finding):
        sid = '-'.join(map(str, (finding.host.ip, finding.protocol, finding.port, finding.svc_name)))
        try:
            self._services[sid]
        except KeyError:
            service = NessusService()
            service.id = sid
            service.finding = finding
            service.host = finding.host
            service.src_file = self._curr_filename
            add_to_host = True
            if self._save_result_lists:
                add_to_host = self._save_to_result_dict(self._services, service)
            if add_to_host:
                # add service to host
                finding.host.services.add(service)

    @staticmethod
    def is_valid_file(file):
        head = VSBaseParser.get_file_head(file, 2)
        if head is None:
            LOGGER.error('Unable to read file: {}'.format(file))
            return False
        else:
            return len(head) > 1 and (head[0].startswith('<?xml') and 'NessusClientData' in head[1])

    def _parse_add_services(self, host):
        service_software = {}

        for finding in host.findings:
            if finding.port < 1:
                continue
            sw_name = ''
            sw_version = ''
            sw_id = (finding.protocol, finding.port, finding.svc_name)
            try:
                detected_software = service_software[sw_id]
            except KeyError:
                detected_software = {}
                service_software[sw_id] = detected_software

            if 'Service detection' == finding.plugin.pluginFamily:
                sw_name = finding.plugin.pluginName[:len(' Server detection')-1]
            else:
                lines = finding.plugin_output.split('\n')
                if finding.plugin.pluginName.endswith(' Server Type and Version'):
                    if 'version' in lines[1]:
                        sw_name = self._get_output_value_by_prefix(lines[1], 'version :')
                    elif len(lines) > 2:
                        line = lines[2]
                        if '/' in line:
                            sw_name, sw_version = line.split('/', 1)
                        elif '(' in line and ')' in line:
                            sw_name, sw_version = line[:line.find(')')-1].split('(')
                            if not any(char.isdigit() for char in sw_version):
                                sw_version = ''
                        else:
                            sw_name = line
                else:
                    for line in lines:
                        for prefix in ('Installed version', 'Reported version'):
                            if line.lstrip(' ').startswith(prefix):
                                sw_version = self._get_output_value_by_sep(line, ':')
                                break

                        if 'Product' in line:
                            sw_name = self._get_output_value_by_sep(line, ':')

            # TODO: normalize name

            sw_name = sw_name.strip(' ')
            sw_version = sw_version.strip(' ')

            if sw_name:
                try:
                    detected_software[sw_name]
                except KeyError:
                    detected_software[sw_name] = set()

                if sw_version:
                    detected_software[sw_name].add(sw_version)

        for service in host.services:
            for proto_port_svc, name_version in service_software.items():
                proto, port, svc = proto_port_svc
                if service.protocol == proto and service.port == port and service.name == svc:
                    for sw_name, versions in name_version.items():
                        for sw_version in versions:
                            for known_sw in service.detected_software:
                                if sw_name == known_sw['name'] and sw_version == known_sw['version']:
                                    break
                            else:
                                service.detected_software.append({'name': sw_name, 'version': sw_version})

    @staticmethod
    def _get_output_value_by_prefix(line, prefix):
        if prefix not in line:
            return ''
        return line[:line.find(prefix)].strip(' ')

    @staticmethod
    def _get_output_value_by_sep(line, sep):
        if sep not in line:
            return ''
        return line.split(sep)[1].strip(' ')
