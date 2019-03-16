from vulnscan_parser.models.vsbase import VSBaseModel


# inheritance from VSCertificate does not apply here
class NessusCertificate(VSBaseModel):

    def __init__(self):
        super().__init__()
        self.finding = None
        self.serial_number = ''
        self.subject = {}
        self.issuer = {}
        self.public_key_len = ''
        self.san = []
        self.signature_algorithm = ''
        self.not_before = ''
        self.not_after = ''
        self.sha1_fingerprint = ''
        self.sha2_fingerprint = ''

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

    def to_serializable_dict(self):
        result = super().to_serializable_dict()
        result['not_before'] = str(result['not_before'])
        result['not_after'] = str(result['not_after'])

        return result
