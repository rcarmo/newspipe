#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# $NoKeywords: $   for Visual Sourcesafe, stop replacing tags
__revision__ = "$Revision: 1.68 $"
__revision_number__ = __revision__.split()[1]
__version__ = "1.1.9"
__date__ = "2005-07-03"
__url__ = "http://newspipe.sourceforge.net"
__author__ = "Ricardo M. Reyes <reyesric@ufasta.edu.ar>"
__contributors__ = ["Rui Carmo <http://the.taoofmac.com/space/>", "Bruno Rodrigues <http://www.litux.org/blog/>", "Stéphane Puybareau <http://puyb.net/>"]
__id__ = "$Id: newspipe.py,v 1.68 2006/01/22 22:02:37 reyesric Exp $"

ABOUT_NEWSPIPE = """
newspipe.py - version %s revision %s, Copyright (C) 2003-%s \n%s
"""%(__version__, __revision_number__, __date__.split('-')[0], __author__)


import os, sys, os.path
from time import sleep, time
from datetime import datetime, timedelta
from lib.cache import *
from pprint import pprint
from lib.utils import *
from lib.utils.opml import *
from lib.utils.diff import *
from lib.utils.cli import *
from lib.utils.markup import *
from lib.utils.mime import *
from lib.utils.log import mylog
from pickle import load, dump
import smtplib
import re
from difflib import SequenceMatcher
import email.Utils
import email.Header
import traceback
import socket, urllib, urllib2
import gc

try:
    import threading as _threading
    has_threading = True
except ImportError:
    import dummy_threading as _threading
    has_threading = False

has_html2text = True
try:
    from html2text import *
except ImportError:
    has_html2text = False
    

PYTHON_VERSION = '.'.join([str(x) for x in sys.version_info])
USER_AGENT = 'NewsPipe/'+__version__+' rev.'+__revision_number__+' Python: '+ PYTHON_VERSION+' Platform: '+sys.platform +' / '+__url__

OPML_DEFAULTS = {
    'active': '1',
    'digest': '0',
    'titles': '1',
    'download_link': '0',
    'diff': '1',
    'check_text': '1',
    'delay': '60',
    'textonly': '0',
    'mobile': '0',
    'download_images': '1',
    'check_time': '',
    'mobile_time': '',
    'remove': '',
}

DEBUG = False



def formatNumber (text):
    i = float(text)
    m = i/(1024*1024)

    if m < 0.01 and m > 0:
        m = 0.01
    return '%0.2f MB' % m




class Channel:
    def __init__(self, title, original, xmlUrl, htmlUrl, download_link, diff, download_images, parameters):
        self.original = original
        self.xmlUrl = xmlUrl
        self.htmlUrl = htmlUrl
        self.title = original.get('title', title)
        self.description = original.get('description', self.title)
        self.creator = original.get('creator', original.get('author', self.title))
        self.download_link = download_link
        self.download_images = download_images
        self.diff = diff
        self.parameters = parameters

    def NewItem(self, original, encoding="utf-8", remove=None):
        return Item(original, self, encoding, remove)





post_history = {}
feed_history = {}





def GetValue (x):
    if isinstance(x, basestring):
        return x
    elif isinstance(x, list):
        try:
            return x[0]['value']
        except:
            return ''
    else:
        return ''





def getException():
    return '\n'.join(traceback.format_exception (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))


html2text_lock = _threading.BoundedSemaphore()


def makeHeader(text):
    if not text:
        text = ''
    if not isinstance(text, unicode):
        text = text.decode('latin1')
    if isinstance(text, unicode):
        text = text.encode('utf-8')
    try:
        if has_html2text:
            text = html2text(text).strip()
    except UnicodeError:
        pass

    return str(email.Header.make_header([(text, 'utf-8')]))


def getPlainText(html, links=True):
    if not isinstance(html, unicode):
        html = html.decode('latin1')

    plain_text = u''
    if has_html2text:
        # html2text seems to be not-thread-safe, so I'm avoiding concurrency
        # here using a semaphore
        html2text_lock.acquire()
        try:
            try:
                plain_text = html2text(html).strip()
            except:
                plain_text = getException ()
                mylog.exception ('Error en getPlainText')
        
        finally:
            html2text_lock.release()
    


    if not isinstance(plain_text, unicode):
        plain_text = plain_text.decode('utf-8')

    return plain_text
    
class Item:
    def __init__(self, original, channel, encoding="utf-8", remove=None):
        global post_history

        if encoding == '': encoding="utf-8"

        for key in original.keys():
            if type(original.get(key)) == type(""):
                original[key] = original[key].decode(encoding, "replace")
        
    

        self.original = original
        self.link = GetValue(original.get('link', channel.htmlUrl))
        if original.has_key('enclosures'):
            self.enclosures = original.enclosures
        else:
            self.enclosures = ()
    

        self.new_text = ''
        self.text_key = 'None'
        for k in 'content body content_encoded description summary summary_detail'.split():
            if k in original.keys():
                if original[k]:
                    self.new_text = original[k]
                    self.text_key = k
                    break
            
        
    
        if self.text_key == None and 'summary_detail' in original.keys() and 'value' in original['summary_detail'].keys():
            self.new_text = original['summary_detail']['value']
            self.text_key = "summary_detail/value"
    

        self.new_text = GetValue (self.new_text)

        if channel.download_link:
            try:
                downloaded_file = cache.urlopen(self.link, max_age=999999, can_pipe=False);
                message = downloaded_file.info['Cache-Result']
                mylog.debug (message + ' ' + self.link)
            except KeyboardInterrupt:
                raise
            except:
                mylog.exception ('Cannot download '+self.link)
                downloaded_file = None
        

            if downloaded_file:
                self.new_text = downloaded_file.content.read()
        
    

        if remove:
            rc = re.compile (remove, re.I+re.S+re.X)
            self.new_text = re.sub(rc, '', self.new_text)

        if type(self.new_text) == type(""):
            try:
                self.new_text = self.new_text.decode(encoding)
            except UnicodeDecodeError, e:
                mylog.debug("Error in " + channel.xmlUrl + ", " + original.get('title', original.get('url', '?')) + ": " + str(e))
                self.new_text = self.new_text.decode(encoding, 'replace')
        
    
        self.new_text = fixEntities(self.new_text)
        self.subject = GetValue (original.get('title', ''))

        if not self.subject:
            sin_html = ' '.join(re.compile('<.+?>').split(self.new_text))

            self.subject = sin_html[:60].strip()

            if '\n' in self.subject:
                self.subject = self.subject.split('\n')[0]
        
            self.subject += '...'
    

        self.urlHash = md5text(
                self.link.encode('utf-8', 'replace'),
                channel.xmlUrl,
                self.subject.encode('utf-8', 'replace')
            )

        self.subject = self.subject

        if 'modified_parsed' in original.keys() and original['modified_parsed'] != None:
            x = original['modified_parsed']
            self.timestamp = datetime(year=x[0], month=x[1], day=x[2], hour=x[3], minute=x[4], second=x[5])
        else:
            self.timestamp = datetime.now()
    

        self.text = self.new_text
        if channel.diff and post_history.has_key(self.urlHash):
            before_diff = self.new_text
            differ = TextDiff(post_history[self.urlHash]['text'], self.new_text)

            self.text = differ.getDiff()
            if self.text <> before_diff:
                self.timestamp = datetime.now()
    

        self.channel = channel

        self.creatorName = GetValue(original.get('creator', original.get('author', channel.creator)))
        # set the default From: address to "rss@domain" where domain comes from the site's url
        self.creatorEmail = 'rss@'+ urlparse.urlparse(channel.htmlUrl)[1]

        # search for an email address, in the item first, then in the channel
        r = re.compile('([A-Za-z0-9_.\+]+@[A-Za-z0-9_.]+)')
        for x in [original.get('creator', ''), original.get('author', ''), channel.creator]:
            try:
                m = r.search(x)
                if m:
                    self.creatorEmail = m.group(1)
            except TypeError:
                pass

        self.is_modified = 'Unknown'

        self.custom_tags = {}
        known_tags = ['text', 'link', 'htmlUrl', 'xmlUrl', 'description', 'path', 'title', 'index'] + OPML_DEFAULTS.keys()
        for k in channel.parameters.keys():
            if not k in known_tags:
                self.custom_tags[k] = channel.parameters[k]

    def __repr__(self):
        #return 'Link: %s\nTimeStamp: %s\ntext: %s' % (self.link, self.timestamp, self.text)
        return self.subject
        #return self.original.__repr__()


    def GetEmail(self, from_email, recipient, format="multipart", encoding='utf-8', include_threading=False, subject_prefix=None, from_address=None):
        global post_history
        template = """
    <p>
        __body__
    </p>
    <hr />
    <p>
        <a href="__htmlUrl__">Home</a>
        &nbsp;&nbsp;&nbsp;
        <a href="__permalink__">Link</a>
        &nbsp;&nbsp;&nbsp;
        __enclosure__
    </p>
"""
        #self.text = expandNumEntities(self.text)

        body = self.text
        text_version = getPlainText (body)
        text_version = text_version + "\n\n" + "Home: [ " + self.channel.htmlUrl + " ]\n" + "Link: [ " + self.link + " ]\n"

        if self.enclosures:
            for enclosure in self.enclosures:
                text_version = text_version + "Enclosure: [ " + enclosure.get('url') + "  (" + formatNumber(enclosure.get('length', '0')) + ") ]\n"
        
    

        html_version = template
        html_version = html_version.replace('__subject__', self.subject)
        html_version = html_version.replace('__body__', body)
        html_version = html_version.replace('__permalink__', self.link)
        html_version = html_version.replace('__htmlUrl__', self.channel.htmlUrl)

        enclosure_text = ""
        if self.enclosures:
            for enclosure in self.enclosures:
                enclosure_text = enclosure_text + "<a href=\"" + enclosure.get('url') + "\"> Enclosure (" + formatNumber(enclosure.get('length', '0')) + ")</a>&nbsp;&nbsp;&nbsp;"
        
        #ed if

        html_version = html_version.replace('__enclosure__', enclosure_text)

        img_search_re = re.compile('<.*?img.+?src.*?=.*?[\'"](.*?)[\'"]', re.IGNORECASE)

        # edit all the image urls that are relative to make them fully qualified
        if self.link:
            urls = re.findall(img_search_re, html_version)
            for url in urls:
                url_parts = urlparse.urlsplit(url)
                if not url_parts[1]:
                    if not url_parts[0].upper() == 'FILE:':
                        full_url = urlparse.urljoin(self.link, url)
                        html_version = html_version.replace (url, full_url)

        images = None
        if format != "plaintext" and self.channel.download_images:
            urls = re.findall(img_search_re, html_version)
            if urls:
                images = []
                seenurls = []
                i = 0
                for url in urls:
                    if url:
                        # check if this url was already proccesed
                        previous = [x['url'] for x in images]
                        if not (url in previous):
                            filename = os.path.basename(url)
                            if '?' in filename:
                                filename = filename[:filename.find('?')]
                            ext = os.path.splitext(url)[1]
                            if '?' in ext:
                                ext = ext[:ext.find('?')]
                        
                            name = '%s%s' % (md5text(filename+str(i)),ext)
                            html_version = html_version.replace(url, 'cid:'+name)
                            images += [{'name':name, 'url':url, 'filename':filename},]
                            i += 1
                    
                
            
                seenurls = None
        
    

        from_email = self.creatorEmail
        if from_email == None:
            from_email = recipient[1]
    

        if subject_prefix:
            subject = subject_prefix + ': ' + self.subject
        else:
            subject = self.subject

        to_header = ', '.join(['"%s" <%s>' % (recipient[0], each.strip()) for each in recipient[1].split(',')])
        if from_address:
            from_header = from_address
        else:
            from_header = '"%s" <%s>' % (makeHeader(self.channel.title), from_email)

        headers = []
        headers.append(('From', from_header))
        headers.append(('To', to_header))
        headers.append(('Subject', makeHeader(subject)))
        msgid = email.Utils.make_msgid()
        headers.append(('Message-ID', msgid))
        headers.append(('Date', self.timestamp.strftime("%a, %d %b %Y %H:%M:%S +0000")))

        headers.append(('X-NewsPipe-Version', '%s (Rev %s, Python %s, %s) %s' % (__version__, __revision_number__, PYTHON_VERSION, sys.platform, __url__)))
        headers.append(('X-Channel-Feed', self.channel.xmlUrl))
        headers.append(('X-Channel-title', makeHeader(self.channel.title)))
        headers.append(('X-Channel-description', makeHeader(self.channel.description)))
        headers.append(('List-Id', '%s <%s>' % ( makeHeader(self.channel.title), self.channel.xmlUrl)))
        headers.append(('Content-Location', self.link))

        for k in self.custom_tags.keys():
            headers.append(('X-Custom-'+k, makeHeader(self.custom_tags[k])))

        if DEBUG:
            headers.append(('X-Channel-x-cache-result', self.channel.original['Cache-Result']))
            headers.append(('X-Item-Attributes', ', '.join(self.original.keys())))
            headers.append(('X-Item-Text-Key', self.text_key))
            headers.append(('X-Item-Modified', self.is_modified))
            headers.append(('X-Item-Hash-Link', md5text(self.link.encode('latin1', 'replace'))))
            headers.append(('X-Item-Hash-Feed', md5text(self.channel.xmlUrl.encode('latin1', 'replace'))))
            headers.append(('X-Item-Hash-Subject', md5text(self.subject.encode('latin1', 'replace'))))
            headers.append(('X-Item-Hash', self.urlHash))
            if images:
                for each in images:
                    headers.append (('X-Image-'+each['name'], each['url']))

        lastid = feed_history[self.channel.xmlUrl].get("lastid", "")
        if lastid == "":
            refid = "<" + md5text(self.channel.xmlUrl) + "@rss.example.com>"
            lastid = refid
        else:
            refid = lastid.split()[-1]
        # endif

        if include_threading:
            headers.append(('In-Reply-To', refid))
            headers.append(('References', lastid))

        if feed_history[self.channel.xmlUrl].has_key("lastid"):
            feed_history[self.channel.xmlUrl]["lastid"] = " ".join( (feed_history[self.channel.xmlUrl]["lastid"] + " " + msgid).split()[-4:] )
        else:
            feed_history[self.channel.xmlUrl]["lastid"] = refid + " " + msgid
        feed_history["modified"]=True

        if format == "plaintext":
            return createTextEmail (text_version, headers, encoding)
        else:
            if( format == "html" ):
                return createHtmlMail (cache, html_version, '', headers, images, None, self.link, encoding)
            else: # multipart
                return createHtmlMail (cache, html_version, text_version, headers, images, None, self.link, encoding)





def send_emails(msgs, method, server, auth, auth_user, auth_pass, procmail, reverse):
    # disable the defaulttimeout to avoid a bug with starttls()
    # the defaulttimeout will be restored at the end of the method
    backup_timeout = socket.getdefaulttimeout ()
    socket.setdefaulttimeout (None)    
  
    try:
        original_msgs = msgs[:]
        splited_msgs = []
        
        # split the message list in groups of 10 messages
        aux = []
        for each in original_msgs:
            if len(aux) == 10:
                splited_msgs.append(aux)
                aux = []

            aux.append(each)
        if aux:
            splited_msgs.append(aux)
        
        for msgs in splited_msgs:
            if reverse:
                msgs.reverse()
    
            if method.lower() in ('smtp', 'both'):
                smtp = smtplib.SMTP(server)
                smtp.set_debuglevel(DEBUG)
                respuesta = smtp.ehlo()
                mylog.debug(repr(respuesta))
    
                # initiate TLS if necesary
                if len(respuesta) == 2:
                    if 'starttls' in respuesta[1].lower():
                        mylog.debug('Initiating TLS conection')
                        smtp.starttls()
                        smtp.ehlo()
                        mylog.debug(repr(respuesta))
                        
                # authenticate with SMTP server when there's need to
                if auth:
                    smtp.login(auth_user,auth_pass);
    
                count = 0;
                for msg in msgs:
                    if msg == None:
                        continue
    
                    fromaddr = msg['From']
    
                    r = re.compile('<(.+?)>')
                    toaddr = r.findall(msg['To'])
    
                    try:
                        # build envelope and send message
                        smtp.sendmail(fromaddr, toaddr, msg.as_string(unixfrom=False))
                        count = count + 1
                        mylog.debug('mail sent to %s from %s ' % (toaddr, fromaddr))
                    except:
                        mylog.exception("Error sending mail")
                        mylog.error(str(msg))
                        raise
    
                try:
                    smtp.quit()
                except socket.sslerror:
                    pass  # connecting to smtp.gmail.com gives this false error
    
                if count != len(msgs):
                    note = " (" + str(len(msgs)-count) +" failed)"
                else:
                    note=""
                mylog.info ('%d emails sent successfully%s via SMTP' % (count,note,))
        
    
            if method.lower() in ('procmail', 'both'):
                count = 0
                for msg in msgs:
                    try:
                        fp = os.popen(procmail, 'w')
                        fp.write(msg.as_string(unixfrom=True))
                        status = fp.close()
                    except:
                        mylog.exception ('IOError executing '+procmail)
                        status = 1
                        raise
    
                    if status is None:
                        count += 1
                
            
                if count != len(msgs):
                    note = " (" + str(len(msgs)-count) +" failed)"
                else:
                    note=""
                mylog.info ('%d emails sent successfully%s via PROCMAIL' % (count,note,))
    finally:
        socket.setdefaulttimeout (backup_timeout)    


def group_items(items, titles, encoding, reverse):
    def cmpItems(x,y):
        if ('modified_parsed' in x.original.keys()) and (x.original['modified_parsed']):
            aux = x.original['modified_parsed']
            tsx = datetime(year=aux[0], month=aux[1], day=aux[2], hour=aux[3], minute=aux[4], second=aux[5])
        else:
            tsx = datetime.now()
    

        if ('modified_parsed' in y.original.keys()) and (y.original['modified_parsed']):
            aux = y.original['modified_parsed']
            tsy = datetime(year=aux[0], month=aux[1], day=aux[2], hour=aux[3], minute=aux[4], second=aux[5])
        else:
            tsy = datetime.now()
    

        return cmp(tsy,tsx)


    items.sort (cmpItems)
    if reverse:
        items.reverse()

    template1 = """
<font face="Arial,Helvetica,Geneva">
    <p>
        <font size=+1>
            <strong>
                <a href="__permalink__">
                    __subject__
                </a>
            </strong>
        </font>
        <br>
        <strong>
            by __creator__
        </strong>
        , __timestamp__
    </p>
    <p>
        __body__
    </p>
    __enclosure__
</font>
<br clear=all />
<hr />
"""

    template2 = """
<font face="Arial,Helvetica,Geneva">
    <p>
       <a href="__permalink__">#</a>&nbsp;
        __body__
    </p>
</font>
"""

    text = ''

    for item in items:
        if titles:
            html_version = template1
        else:
            html_version = template2
    
        html_version = html_version.replace('__permalink__', item.link)
        html_version = html_version.replace('__subject__', item.subject)
        html_version = html_version.replace('__body__', item.text)
        html_version = html_version.replace('__creator__', '<a href="mailto:%s">%s</a>' % (item.creatorEmail, item.creatorName))
        html_version = html_version.replace('__timestamp__', item.timestamp.strftime("%a, %d %b %Y %H:%M:%S +0000"))

        enclosure_text = ""
        if item.enclosures:
            for enclosure in item.enclosures:
                enclosure_text = enclosure_text + "<a href=\"" + enclosure.get('url') + "\"> Enclosure (" + formatNumber(enclosure.get('length', '0')) + ")</a>&nbsp;&nbsp;&nbsp;"
        
        #ed if

        html_version = html_version.replace('__enclosure__', '<p>'+enclosure_text+'</p>')

        text += html_version

    dicc = {}
    dicc['body'] = text
    dicc['title'] = '%s (%d items)' % (items[0].channel.title, items.__len__())
    dicc['link'] = items[0].channel.htmlUrl
    if 'modified_parsed' in items[0].original.keys():
        dicc['modified_parsed'] = items[0].original['modified_parsed']


    customs = {}
    for each in items:
        for k, v in each.custom_tags.items():
            if k in customs.keys():
                if not v in customs[k]:
                    customs[k] += ' '+ v
            else:
                customs[k] = v

    for k,v in customs.items():
        dicc[k] = v

    return items[0].channel.NewItem(dicc, encoding)



def CargarHistoricos(name):
    if isinstance(name, unicode):
        name = name.encode('latin1', 'replace')

    data_dir = os.path.normpath(os.path.join(HOME, '.newspipe/data'))

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    try:
        if feed_history:
            del(feed_history)
    
    except UnboundLocalError:
        pass

    try:
        file_name = os.path.join(data_dir, name+'.feeds')
        feed_history = load(open(file_name))
        mylog.debug('Loading feed archive '+name+'.feeds')
    except:
        try:
            mylog.debug('Archive not found. Trying backup file '+name+'.feeds.bak')
            file_name = os.path.join(data_dir, name+'.feeds.bak')
            feed_history = load(open(file_name))
        except:
            feed_history = {}

    try:
        if post_history:
            del(post_history)
    
    except UnboundLocalError:
        pass

    try:
        file_name = os.path.join(data_dir, name+'.posts')
        mylog.debug('Loading post archive '+name+'.posts')
        post_history = load(open(file_name))
    except:
        try:
            mylog.debug('Archive not found. Trying backup file '+name+'.posts.bak')
            file_name = os.path.join(data_dir, name+'.posts.bak')
            post_history = load(open(file_name))
        except:
            post_history = {}

    feed_history['modified'] = False
    post_history['modified'] = False

    return feed_history, post_history


def GrabarHistorico(dicc, name, extension):
    if isinstance(name, unicode):
        name = name.encode('latin1', 'replace')

    data_dir = os.path.normpath(os.path.join(HOME, '.newspipe/data'))

    mylog.debug('Saving archive '+name+extension)
    dump(dicc, open(os.path.join(data_dir, name + extension +'.new'), 'w'))

    try: os.remove (os.path.join(data_dir, name+extension+'.bak'))
    except OSError: pass
    try: os.rename (os.path.join(data_dir, name+extension), os.path.join(data_dir, name+extension+'.bak'))
    except OSError: pass

    os.rename (os.path.join(data_dir, name+extension+'.new'), os.path.join(data_dir, name+extension))
    dicc['modified'] = False



class FeedWorker (_threading.Thread):
    def __init__(self, feeds_queue, email_queue, config, email_destino, movil_destino, semaforo):
        self.config = config
        self.email_destino = email_destino
        self.movil_destino = movil_destino
        self.semaforo = semaforo

        self.feeds_queue = feeds_queue
        self.email_queue = email_queue

        _threading.Thread.__init__(self)


    def run(self):
        config = self.config
        _email_destino = self.email_destino
        movil_destino = self.movil_destino
        semaforo = self.semaforo

        while True:
            gc.collect()
            feed = self.feeds_queue.get()
            if feed is None:
                break
        

            url = feed['xmlUrl']
            try:
                time = feed.get('check_time', None)
                if time:
                    parsed_time = parseTimeRange(time)
                    if parsed_time:
                        if not checkTime (parsed_time):
                            mylog.debug ('Ignoring the feed '+url)
                            continue
                    else:
                        mylog.error ('Error parsing the time range "%s" in the feed %s' % (time, url))

                items = []

                semaforo.acquire()
                if not feed_history.has_key(url):
                    feed_history[url] = {}
                    feed_history[url]['ultimo_check'] = None
                    feed_history[url]['proximo_check'] = None
                    feed_history[url]['ultima_actualizacion'] = None
                    feed_history[url]['delay'] = None
                    feed_history['modified'] = True
            
                semaforo.release()

                ultimo_check           = feed_history[url]['ultimo_check']
                proximo_check          = feed_history[url]['proximo_check']
                ultima_actualizacion   = feed_history[url].get('ultima_actualizacion', None)
                delay                  = feed_history[url].get('delay', None)

                ahora = datetime.now()
                if proximo_check and ahora < proximo_check:
                    continue
            

                title = feed.get('title', feed.get('text', url))
                mylog.debug ('Processing '+title)

                email = feed.get('ownerEmail', None)
                if email:
                    #mylog.debug ('email[0]=' + _email_destino[0] + ', email[1]=' + _email_destino[1])
                    #mylog.debug ('Overriding email: ' +email)
                    email_destino = _email_destino[0], email
                else:
                    email_destino = _email_destino
            


                auth = feed.get('auth', None)
                if auth:
                    if ':' in auth:
                        username, password = auth.split(':')
                    else:
                        mylog.error ('The "auth" parameter for the feed '+title+' is invalid')
                        continue
                
                else:
                    username, password = None, None
            

                xml = None
                try:
                    xml = cache.feed_parse(url, config['can_pipe'] == '1', username, password)
                except cache.SocketTimeoutError:
                    mylog.info ('Timeout error downloading %s' % url)
                    mylog.debug ('Will retry in the the next pass')
                    continue
                except cache.HTTPError, e:
                    mylog.info ('HTTP Error %d downloading %s' % (e.code, url,))
                except cache.URLError, e:
                    mylog.info ('URLError (%s) downloading %s' % (e.reason, url,))
                except cache.OfflineError:
                    mylog.info ('Resource unavailable when offline (%s)' % url)
                except Exception, e:
                    mylog.exception ('Error %s downloading %s' % (str(e), url))

                if xml:
                    mylog.debug (xml['channel']['Cache-Result'] + ' ' + url)
                    channel = Channel(title, xml['channel'], url, feed['htmlUrl'], feed['download_link'] == '1', feed['diff'] == '1', feed['download_images'] == '1', feed)
                    for elemento in xml['items']:
                        item = channel.NewItem(elemento, xml["encoding"], feed['remove'])

#                         for k in item.keys():
#                             mylog.debug('Key: ' + str(k))

                        if post_history.has_key(item.urlHash):
                            post_history[item.urlHash]['timestamp'] = datetime.now()
                            post_history['modified'] = True

                            check_text = feed['check_text'] == '1'

                            if check_text:
                                if item.new_text.strip() == post_history[item.urlHash]['text'].strip():
                                    continue
                            
                            else:
                                continue
                        

                            item.is_modified = 'True'
                        else:
                            item.is_modified = 'False'
                    

                        items.append(item)
                
            

                if items:
                    mylog.info ('%d new items in %s' % (items.__len__(),title))
                else:
                    mylog.debug ('No change in %s' % (title,))
            

                items_sin_agrupar = items[:]

                if (len(items) >= 1) and (feed['digest'] == '1'):
                    lista_vieja = items[:]
                    items = [group_items(lista_vieja, feed['titles'] == '1', config['encoding'], config['reverse'] == '1')]
            

                email_ok = True
                envio = config.get( 'sender', email_destino[1] )
                if(config['multipart'] == 'off'):
                     format = "html"
                else:
                     format = "multipart"
                if((config['textonly'] == '1') or (feed['textonly'] == '1')):
                    format = "plaintext"

                encoding = config['encoding']
                include_threading = config['threading'] == '1'
                subject_prefix = config['subject']

                for item in items:
                    self.email_queue.put(item.GetEmail(envio, email_destino, format, encoding, include_threading, subject_prefix, config['from_address']))
            

                # second pass for mobile copy, provided we could send the first one
                if( (feed['mobile'] == '1' ) and movil_destino and email_ok ):
                    send = False

                    time = feed.get('mobile_time', None)
                    if time:
                        parsed_time = parseTimeRange(time)
                        if parsed_time:
                            if checkTime (parsed_time):
                                send = True
                        else:
                            mylog.error ('Error parsing the time range "%s" in the feed %s' % (time, url))

                    if send:
                        for item in items:
                            self.email_queue.put(item.GetEmail(envio, movil_destino, "plaintext", encoding, include_threading, subject_prefix))
                    
                
            

                if email_ok:
                    for item in items_sin_agrupar:
                        post_history[item.urlHash] = {'text':item.new_text, 'timestamp':datetime.now()}
                        post_history['modified'] = True
                

                    # get the time until next check, 60 minutos by default
                    delay = int(feed['delay'])

                    ###semaforo.acquire()
                    feed_history[url]['ultimo_check'] = datetime.now()
                    feed_history[url]['proximo_check'] = datetime.now() + timedelta(minutes=delay)
                    if items.__len__() > 0:
                        feed_history[url]['ultima_actualizacion'] = datetime.now()
                    feed_history[url]['delay'] = delay
                    feed_history['modified'] = True
                    ###semaforo.release()
            
            except:
                mylog.exception ('Exception processing '+url)
    



def setPriority (priority):
    # 0 = Low priority
    # 1 = Normal priority
    # 2 = High priority

    if priority == 1:
        pass
    elif priority == 2:
        raise NotImplementedError('High priority mode not implemented yet')
    elif priority == 0:
        if sys.platform.lower().startswith('win'):
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                thread = kernel32.GetCurrentThread()
                kernel32.SetThreadPriority(thread, -15)
                mylog.debug ("Thread priority lowered.")
            except ImportError:
                mylog.error ('CTypes module is not available. The parameter "priority" will be ignored')
                pass
        else:
            raise NotImplementedError ('Priority settings only implemented in Windows')
    else:
        raise ValueError ('The parameter "priority" has an invalid value (%d)' % priority)


def MainLoop():
    global post_history
    global feed_history
    global cache
    global DEBUG


    semaforo = _threading.BoundedSemaphore()
    feed_history, post_history = None, None

    while True:
        config = ReadConfig()

        DEBUG = config['debug'] == '1'

        log_dir = os.path.normpath(os.path.join(HOME, '.newspipe/log'))
        mylog.logFile(config['log_console']  == '1', 'newspipe', log_dir, DEBUG)
        
        gc.collect()

        if DEBUG:
            mylog.warning ('DEBUG MODE')
    

        mylog.debug ('Home directory: ' + HOME)

        try:
            mylog.debug ('Configuration settings:')
            mylog.debug ('-'*30)
            for x,y in config.items():
                mylog.debug ('%s: %s', x, y)
        
            mylog.debug ('-'*30)

            setPriority (int(config['priority']))

            cache.offline = config['offline'] == '1'
            if cache.offline:
                mylog.warning('Working offline')
        

            cache.debug = DEBUG

            if CheckOnline(config):
                NUM_WORKERS = int(config['workers'])

                if not has_threading:
                    mylog.warning ('Running without threads support')
                    NUM_WORKERS = 1

                filename = config['opml']

                opml = None
                try:
                    source_path = os.path.split(sys.argv[0])[0]
                    for p in ('.', source_path):
                        if os.path.exists (os.path.join(p, filename)):
                            filename = os.path.join(p, filename)
                            break

                    fp = cache.urlopen(filename, max_age=60, can_pipe=False).content
                    opml = flatten_tree(ParseOPML(fp), OPML_DEFAULTS)
                    mylog.debug ('Processing file: '+filename)
                except cache.URLError:
                    mylog.error ('Cannot find the opml file: '+filename)
                    opml = None
                except:
                    mylog.exception ('Error parsing file: '+filename)
                    opml = None

                if opml:
                    email_destino = (opml['head']['ownerName'].strip('"'), opml['head']['ownerEmail'])
                    if( opml['head'].has_key('ownerMobile') ):
                        movil_destino = (opml['head']['ownerName'].strip('"'), opml['head']['ownerMobile'])
                    else:
                        movil_destino = False

                    if opml['head'].has_key('fromEmail'):
                        name = opml['head'].get('fromName', 'Newspipe')
                        from_address = name.strip('"') + ' <' + opml['head']['fromEmail'] + '>'
                        config['from_address'] = from_address

                    if not feed_history or not post_history:
                        feed_history, post_history = CargarHistoricos(opml['head']['title'])

                    feeds_queue = Queue.Queue(0)
                    email_queue = Queue.Queue(0)

                    mylog.debug ('Inserting the feeds into the pending queue')
                    for feed in opml['body']:
                        if feed['active'] == '1':
                            feeds_queue.put(feed)
                        else:
                            mylog.debug ('Ignoring the Inactive feed: '+feed['xmlUrl'])
                

                    mylog.debug ('Inserting the end-of-work markers in the queue')
                    for x in range(NUM_WORKERS):
                        feeds_queue.put(None)
                

                    mylog.debug ('Starting working threads')
                    workers = []
                    for x in range(NUM_WORKERS):
                        w = FeedWorker (feeds_queue, email_queue, config, email_destino, movil_destino, semaforo)
                        workers.append(w)
                        w.start()
                

                    mylog.debug ('Waiting for all the threads to finish')
                    for w in workers:
                        w.join()
                

                    mylog.debug ('Extracting the emails from the results queue')
                    emails = []
                    while True:
                        try:
                            email = email_queue.get_nowait()
                            emails += [email,]
                        except Queue.Empty:
                            break
                    
                

                    try:
                        send_emails (emails, config['send_method'], config['smtp_server'], config['smtp_auth'] == '1',config['smtp_user'],config['smtp_pass'], config['procmail'], config['reverse'] == '1')
                        mensajes_enviados = True
                    except:
                        mylog.exception ('Unhandled exception while sending emails')
                        mensajes_enviados = False
                

                    mylog.debug (filename + ' finished.')

                    if mensajes_enviados:
                        # borrar las entradas del historico que son demasiado viejas
                        for hash, value in post_history.items():
                            if hash == 'modified':
                                continue
                            timestamp = value['timestamp']
                            delta = timedelta(days = 30) # borrar lo que tenga mas 30 dias de antiguedad - maybe this should be configurable too
                            if (datetime.now() - delta) > timestamp:
                                del post_history[hash]
                                post_history['modified'] = True
                        
                    
                        if post_history['modified']:
                            GrabarHistorico (post_history, opml['head']['title'], '.posts')
                        if feed_history['modified']:
                            GrabarHistorico (feed_history, opml['head']['title'], '.feeds')
                
            
        

            # erase from the cache anything older than 10 days - to be made configurable?
            try:
                cache.purge(10)
            except:
                mylog.exception ('Unhandled exception when purging the cache')
        

            if int(config['sleep_time']) == 0:
                break
            else:
                del(feed_history)
                del(post_history)
                feed_history, post_history = None, None

                mylog.debug ('Going to sleep for %s minutes' % (config['sleep_time'],))
                try:
                    sleep(int(config['sleep_time'])*60)
                except KeyboardInterrupt:
                    return
            
        
        except:
            mylog.exception ('Unhandled exception')
            raise  # stop the loop, to avoid infinite exceptions loops ;)




if __name__ == '__main__':

    HOME = None
    for name in ('appdata', 'HOME'):
        HOME = HOME or os.environ.get(name, None)

    # if it can't find the home directory trough environment vars, then 
    # return the path to this script.
    HOME = HOME or os.path.split(sys.argv[0])[0]

    cache_dir = os.path.normpath(os.path.join(HOME, '.newspipe/cache'))
    cache = Cache(cache_dir, agent=USER_AGENT)
    try:
        MainLoop()
    except KeyboardInterrupt:
        sys.exit(0)

