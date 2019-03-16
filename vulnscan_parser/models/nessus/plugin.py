from vulnscan_parser.models.vsbase import VSBaseModel


class NessusPlugin(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.append('script_copyright')
        self.pluginID = 0
        self.pluginName = ''
        self.findings = set()
        self.hosts = set()
