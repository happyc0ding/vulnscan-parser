from vulnscan_parser.models.vsfinding import VSFinding


class SslyzeFinding(VSFinding):

    def __init__(self):
        super().__init__()
        self.ignored_dict_props.append('vulnerability')
        self.vulnerability = None

    def to_serializable_dict(self):
        result = self.vulnerability.to_serializable_dict()
        result.update(self.host.to_serializable_dict())
        result.update(super().to_serializable_dict())
        # remove unnecessary attrs
        result.pop('hostnames')

        return result
