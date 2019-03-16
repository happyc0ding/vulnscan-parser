from vulnscan_parser.models.vshost import VSHost


class MetasploitHost(VSHost):

    def __init__(self):
        super().__init__()
        del self.certificates

    @property
    def address(self):
        return self.ip

    @address.setter
    def address(self, value):
        self.ip = value

    @property
    def name(self):
        try:
            return self.hostnames[0]['name']
        except KeyError:
            return ''

    @name.setter
    def name(self, value):
        self.add_hostname(value, '')
