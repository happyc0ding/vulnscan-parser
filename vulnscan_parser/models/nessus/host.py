from vulnscan_parser.models.vshost import VSHost


class NessusHost(VSHost):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.append('name')
        self.plugins = set()
