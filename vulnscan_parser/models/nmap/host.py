from vulnscan_parser.models.vshost import VSHost


class NmapHost(VSHost):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.append('scripts')
        self.scripts = set()

    @property
    def address(self):
        return self.ip

    @address.setter
    def address(self, value):
        self.ip = value
