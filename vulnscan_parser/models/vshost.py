from vulnscan_parser.models.vsbase import VSBaseModel


class VSHost(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.extend(['certificates', 'services'])
        self.ip = ''
        self.hostnames = []
        #self.ports = set()
        self.findings = set()
        self.certificates = set()
        self.services = set()
        self.src_file = set()

    def add_hostname(self, name, lookup_type):
        newhn = {
            'name': name,
            'type': lookup_type,
        }
        self.add_hostname_dict(newhn)

    def add_hostname_dict(self, hn_dict):
        for hn in self.hostnames:
            if hn == hn_dict:
                break
        else:
            self.hostnames.append(hn_dict)

    def to_serializable_dict(self):
        result = super().to_serializable_dict()
        #result['ports'] = list(self.ports)
        result['src_file'] = list(self.src_file)

        return result

    def __repr__(self):
        return f'{self.__class__.__name__}(ip={self.ip},hostnames={self.hostnames},src_file={self.src_file})'
