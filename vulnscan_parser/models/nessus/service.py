from vulnscan_parser.models.vsservice import VSService


class NessusService(VSService):

    def __init__(self):
        super().__init__()
        self.finding = None
        self.detected_software = []

    @property
    def name(self):
        return self.finding.svc_name

    @property
    def protocol(self):
        return self.finding.protocol

    @property
    def port(self):
        return self.finding.port

    @property
    def pluginID(self):
        return self.finding.plugin.pluginID

