class TextDiff:
    """Create diffs of text snippets."""

    def __init__(self, source, target):
        """source = source text - target = target text"""
        self.separators = '"<>'
        self.nl = "<NL>"
        #self.delTag = "<span class='deleted'>%s</span>"
        self.delTag = '<font color="#FF0000"><STRIKE>%s</STRIKE></font>'
        #self.insTag = "<span class='inserted'>%s</span>"
        self.insTag = '<font color="#337700"><b>%s</b></font>'
        self.source = self.SplitHTML(source.replace("\n", "\n%s" % self.nl))
        self.target = self.SplitHTML(target.replace("\n", "\n%s" % self.nl))
        self.deleteCount, self.insertCount, self.replaceCount = 0, 0, 0
        self.diffText = None
        self.cruncher = SequenceMatcher(None, self.source, self.target)
        self._buildDiff()


    def SplitHTML(self, text):
        old = re.compile('(<.+?>)').split(text)
        new = []
        for x in old:
            if re.compile('<.+>').search(x):
                new.append(x)
            else:
                new.append(x.split())
        return new

    def _buildDiff(self):
        """Create a tagged diff."""
        outputList = []
        for tag, alo, ahi, blo, bhi in self.cruncher.get_opcodes():
            if tag == 'replace':
                # Text replaced = deletion + insertion
                outputList.append(self.delTag % " ".join(self.source[alo:ahi]))
                outputList.append(self.insTag % " ".join(self.target[blo:bhi]))
                self.replaceCount += 1
            elif tag == 'delete':
                # Text deleted
                outputList.append(self.delTag % " ".join(self.source[alo:ahi]))
                self.deleteCount += 1
            elif tag == 'insert':
                # Text inserted
                outputList.append(self.insTag % " ".join(self.target[blo:bhi]))
                self.insertCount += 1
            elif tag == 'equal':
                # No change
                outputList.append(" ".join(self.source[alo:ahi]))
        diffText = " ".join(outputList)
        diffText = " ".join(diffText.split())
        self.diffText = diffText.replace(self.nl, "\n")

    def getStats(self):
        "Return a tuple of stat values."
        return (self.insertCount, self.deleteCount, self.replaceCount)

    def getDiff(self):
        "Return the diff text."
        aux = self.diffText
        return aux