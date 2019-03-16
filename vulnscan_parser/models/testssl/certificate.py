from vulnscan_parser.models.vsbase import VSBaseModel


# class does not inherit VSCertificate for now
class TestsslCertificate(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.finding = None
        self.m_public_key_algorithm = ''

    @property
    def ip(self):
        return self.finding.host.ip

    @property
    def protocol(self):
        return self.finding.protocol

    @property
    def port(self):
        return self.finding.port

    @property
    def hostname(self):
        return self.finding.hostname
