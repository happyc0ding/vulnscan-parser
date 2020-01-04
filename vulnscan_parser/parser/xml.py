from vulnscan_parser.parser.base import VSBaseParser


class VsXmlParser(VSBaseParser):

    def __init__(self):
        super().__init__()
        # restriction in lxml (huge_tree=False), disabled by default. enable this if you have to parse huge trees
        self.allow_huge_trees = False

    def parse(self, filepath, huge_tree=False):
        raise NotImplemented()
