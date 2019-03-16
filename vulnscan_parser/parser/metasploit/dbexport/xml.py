import logging
from pprint import pprint
from collections import OrderedDict
import os
from itertools import islice

# try lxml, but use built-in as fallback
try:
    from lxml import etree as elmtree
except ImportError:
    from xml.etree import ElementTree as elmtree

from vulnscan_parser.parser.metasploit.msf import MetasploitParser
from vulnscan_parser.models.metasploit.host import MetasploitHost
from vulnscan_parser.models.metasploit.service import MetasploitService

# from vulnscan_parser.models.metasploit.finding import MetasploitFinding


LOGGER = logging.getLogger(__name__)


class MetasploitParserXML(MetasploitParser):

    ATTR_BLACKLIST = [
        'notes',
        'host-id'
    ]

    def __init__(self):
        super().__init__()

    def parse(self, filepath):
        self._curr_filename = os.path.basename(filepath)
        self._curr_file_hash = self.hash_file(filepath)

        for event, element in elmtree.iterparse(filepath, tag='host'):
            address = element.find('./address').text
            for host_prop_elm in element.iterchildren():
                if host_prop_elm.tag in self._attr_blacklist:
                    continue

                host = self.add_get_host(address)

                if 'services' == host_prop_elm.tag:
                    for service_elm in host_prop_elm.iterfind('./service'):
                        service = MetasploitService()
                        for service_prop_elm in service_elm.iterchildren():
                            if service_prop_elm.tag in self._attr_blacklist:
                                continue
                            text = ''
                            if service_prop_elm.text is not None:
                                text = service_prop_elm.text.strip()
                            tag = service_prop_elm.tag
                            if 'id' == tag:
                                tag = 'service_id'
                            setattr(service, tag, text)

                        self.save_service(service, host)
                elif 'vulns' == host_prop_elm.tag:
                    # TODO
                    pass
                    #for vuln_elm in host_prop_elm.iterfind('./vuln'):
                else:
                    text = ''
                    if host_prop_elm.text is not None:
                        text = host_prop_elm.text.strip()
                    tag = host_prop_elm.tag
                    if 'id' == tag:
                        tag = 'host_id'
                    setattr(host, tag, text)
            break
