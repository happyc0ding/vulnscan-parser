# vulnscan-parser
Parse scan results into python objects, i.e. Nessus, Nmap, testssl, metasploit, ...

This tool parses verious scan results while trying to map them to a more or less similar structure. All parsers are memory efficient, huge files should not cause any problems.

Currently supported:
* Nessus (v2)
* testssl (3.0)
* Nmap (XML)
* Sslyze (Json and Json pretty)
* sslscan (XML from rbsec)

Some values are modified and due to the insanity of the various formats some compromises are necessary between trying to keep the original naming and structure and a sane data model to work with.

Parsing multiple files via the "parse()" method is possible, parsing overlapping files also works. Host objects are only created once per parser instance while findings, services etc. are being added, if they do not exist yet.

I'm pretty sure there are still some bugs left.

## Important
This code is under development.

# Requirements
Python 3, see requirements.txt / setup.py

# Usage
Just import the parser and work on the results.
```
from vulnscan_parser.parser.nessus.xml import NessusParserXML

nessus_parser = NessusParserXML()
nessus_parser.parse('some/file.nessus')
for finding_id, finding in nessus_parser.findings.items():
  print(finding.pluginID)
  print(finding.pluginName)
  print(finding.plugin_output)

for ip, host in nessus_parser.hosts.items():
  print(host.ip)
  print(host.hostnames)
```
