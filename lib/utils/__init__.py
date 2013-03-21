import urllib2
from log import mylog
from hashlib import md5

def CheckOnline(config):
    if config.has_key('check_online'):
        url = config['check_online']
        try:
            mylog.debug ('Checking online status (downloading '+url+')')
            urllib2.urlopen(url)
            mylog.debug ('Status: online')
            return True
        except:
            mylog.debug ('Status: offline')
            return False
    else:
        return True

def md5text(*args):
    m = md5()
    for i in args:
        m.update(str(i))
    return m.hexdigest()
