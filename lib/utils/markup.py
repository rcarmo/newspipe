import re
from htmlentitydefs import  *
import urlparse

def intEnt(m):
    m = int(m.groups(1)[0])
    return unichr(m)

def xEnt(m):
    m = int(m.groups(1)[0], 16)
    return unichr(m)

def nameEnt(m):
    m = m.groups(1)[0]
    if m in entitydefs.keys():
        return entitydefs[m].decode("latin1")
    else:
        return "&"+m+";"


def expandNumEntities(text):
    text = re.sub(r'&#(\d+);', intEnt, text)
    text = re.sub(r'&#[Xx](\w+);', xEnt, text)
    text = re.sub(r'&(.*?);', nameEnt, text)
    return text

def expandEntities(text):
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&quot;", '"')
    text = text.replace("&ob;", "{")
    text = text.replace("&cb;", "}")
    text = text.replace("&middot;", "*")
    text = re.sub("&[rl]squo;", "'", text)
    text = re.sub("&[rl]dquo;", '"', text)
    text = re.sub("&([aeiouAEIOU])(grave|acute|circ|tilde|uml|ring);", lambda m: m.groups(1)[0], text)
    text = re.sub("&([cC])(cedil);", lambda m: m.groups(1)[0], text)
    text = re.sub("&([n])(tilde);", lambda m: m.groups(1)[0], text)
    text = re.sub(r'&#(\d+);', intEnt, text)
    text = re.sub(r'&#[Xx](\w+);', xEnt, text)
    text = re.sub("&(#169|copy);", "(C)", text)
    text = re.sub("&mdash;", "--", text)
    text = re.sub("&amp;", "&", text)
    return text
    
def getEntity(m):
    v = int(m.groups(1)[0])
    if v in codepoint2name.keys():
        return '&'+codepoint2name[v]+';'
    else:
        return ''

def SanitizeText (text):

    text = text.replace('\n', ' ')

    entitys = entitydefs
    inverso = {}
    for i,j in entitys.items():
        inverso[j] = '&'+i+';'

    chars = filter(lambda x: ord(x) >= 128, text)
    if chars:
        for c in chars:
            if inverso.has_key(c):
                text = text.replace(c, inverso[c])
            else:
                text = text.replace(c, '')


    text = re.sub(r'&#(\d+);', getEntity, text)
    return text
    

entitydefs2 = {}
for key,value in entitydefs.items():
    entitydefs2[value] = key

def urlEncodeNonAscii(b):
    return re.sub('[\x80-\xFF]', lambda c: '%%%02x' % ord(c.group(0)), b)

def iriToUri(iri):
    parts = urlparse.urlparse(iri)
    return urlparse.urlunparse(
        part.encode('idna') if parti==1 else urlEncodeNonAscii(part.encode('utf-8'))
        for parti, part in enumerate(parts)
    )

def fixEntities(text):
    '''This function replaces special characters with &entities; '''
    if not text:
        return text
    if not isinstance(text, unicode):
        text = text.decode('latin1')
    result = ''
    #FIXME: we don't handle the case when the url contains an escaped quote (\").
    exclude_re = re.compile('''(< *img.*?src=['"]|< *a.*?href=['"]|< *link.*?href=['"])(.*?)['"]''', re.IGNORECASE)
    while True:
        match = exclude_re.search(text)
        if match:
            text2 = text[:match.start(2)]
        else:
            text2 = text

        for c in text2:
            if not (c in ('<', '>', '/', '"', "'", '=', '&')):
                if c.encode("latin1", 'replace') in entitydefs2.keys():
                    rep = entitydefs2[c.encode("latin1", "replace")]
                    rep = '&'+rep+';'
                    result += rep
                else:
                    result += c
            else:
                result += c
        if match:
            result += iriToUri(match.group(2))
            text = text[match.end(2):]
        else:
            break
    return result
