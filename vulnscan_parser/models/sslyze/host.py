from vulnscan_parser.models.vshost import VSHost

# host class
class SslyzeHost(VSHost):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.extend(['accepted_ciphers', 'preferred_ciphers', 'certificates'])
        self.accepted_ciphers = []
        self.preferred_ciphers = []

