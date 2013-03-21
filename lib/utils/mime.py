import os, sys, logging
import cStringIO
import MimeWriter, mimetools, email
import socket
from urllib2 import HTTPError, URLError
import urlparse 
import base64
from log import mylog

log = logging.getLogger()

def createHtmlMail(cache, html, text, headers, images=None, rss_feed=None, link=None, encoding='utf-8'):
    """Create a mime-message that will render HTML in popular MUAs, text in better ones"""

    if not isinstance(text, unicode):
        text = text.decode('latin1')

    if isinstance(text, unicode):
        text = text.encode('utf-8')

    if not isinstance(html, unicode):
        html = html.decode('latin1')

    if isinstance(html, unicode):
        html = html.encode('utf-8')


    out = cStringIO.StringIO() # output buffer for our message
    htmlin = cStringIO.StringIO(html)
    txtin = cStringIO.StringIO(text)
    if rss_feed:
        rssin = cStringIO.StringIO(rss_feed)


    writer = MimeWriter.MimeWriter(out)
    #
    # set up some basic headers... we put subject here
    # because smtplib.sendmail expects it to be in the
    # message body
    #

    for x,y in headers:
        writer.addheader(x, y.encode('utf-8'))

    writer.addheader("MIME-Version", "1.0")
    #
    # start the multipart section of the message
    # multipart/alternative seems to work better
    # on some MUAs than multipart/mixed
    #
    writer.startmultipartbody("alternative")
    writer.flushheaders()

    #
    # the plain text section
    #
    if(text != ""):
        subpart = writer.nextpart()
        subpart.addheader("Content-Transfer-Encoding", "quoted-printable")
        pout = subpart.startbody("text/plain", [("charset", 'utf-8'), ("delsp", 'yes'), ("format", 'flowed')])
        mimetools.encode(txtin, pout, 'quoted-printable')
        pout.write (txtin.read())
        txtin.close()

    #
    # start the html subpart of the message
    #
    if images:
        htmlpart = writer.nextpart()
        htmlpart.startmultipartbody("related")
        subpart = htmlpart.nextpart()
    else:
        subpart = writer.nextpart()
    subpart.addheader("Content-Transfer-Encoding", "quoted-printable")
    #
    # returns us a file-ish object we can write to
    #
    pout = subpart.startbody("text/html", [("charset", 'utf-8')])
    mimetools.encode(htmlin, pout, 'quoted-printable')
    htmlin.close()

    if images:
        for x in images:
            try:
                ext = 'gif'
                path, filename = os.path.split(x['url'])
                if filename:
                    name, ext = os.path.splitext(filename)
                    if ext:
                        ext = ext[1:]

                        if '?' in ext:
                            ext = ext[:ext.find('?')]
                if link:
                    # if the url is relative, then add the link url to form an absolute address
                    url_parts = urlparse.urlsplit(x['url'])
                    if not url_parts[1]:
                        if not url_parts[0].upper() == 'FILE:':
                            x['url'] = urlparse.urljoin(link, x['url'])
            
                x['url'] = x['url'].replace(' ', '%20')

                retries = 0;
                MAX_RETRIES = 3;
                img_referer = link
                resource = None
                while retries < MAX_RETRIES:
                    retries += 1

                    # try to fetch the image.
                    # in case of Timeout or URLError exceptions, retry up to 3 times
                    try:
                        resource = cache.urlopen(x['url'], max_age=999999, referer=img_referer, can_pipe=False)
                    except cache.HTTPError, e:
                        # in case of HTTP error 403 ("Forbiden") retry without the Referer
                        if e.code == 403 and img_referer:
                            mylog.info ('HTTP error 403 downloading %s, retrying without the referer' % (x['url'],))
                            img_referer = None
                        else:
                            raise
                    
                    except (cache.SocketTimeoutError, cache.SocketError):
                        mylog.info ('Timeout error downloading %s' % (x['url'],))
                        if retries == MAX_RETRIES:
                            raise
                    
                    except cache.URLError, e:
                        mylog.info ('URLError (%s) downloading %s' % (e.reason, x['url'],))
                        if retries == MAX_RETRIES:
                            raise
                    
                    except Exception:
                        raise # any other exception, kick it up, to be handled later
                    else:
                        # if there's no exception, break the loop to continue
                        # processing the image
                        break
                

                    mylog.info ('Retrying, %d time' % retries);
            

                if not resource:
                    raise Exception('Unknown problem')
            

                message = resource.info['Cache-Result']

                mylog.debug (message + ' ' + x['url'])

                info = resource.info
                content_type = info['Content-Type']
            

                subpart = htmlpart.nextpart()
                subpart.addheader("Content-Transfer-Encoding", "base64")
                subpart.addheader("Content-ID", "<" + x['name'] + ">")
                subpart.addheader("Content-Location", x['name'])
                subpart.addheader("Content-Disposition", "inline; filename=\"" +x['filename'] + "\"" )
                f = subpart.startbody(content_type, [["name", x['name']]])
                b64 = base64.encodestring(resource.content.read())
                f.write(b64)
                image_ok = True  # the image was downloaded ok
            except KeyboardInterrupt:
                raise
            except cache.SocketTimeoutError:
                mylog.info ('Timeout error downloading %s' % (x['url'],))
                image_ok = False
            except cache.HTTPError, e:
                mylog.info ('HTTP Error %d downloading %s' % (e.code, x['url'],))
                image_ok = False
            except cache.URLError, e:
                mylog.info ('URLError (%s) downloading %s' % (e.reason, x['url'],))
                image_ok = False
            except cache.OfflineError:
                mylog.info ('Resource unavailable when offline (%s)' % x['url'])
                image_ok = False
            except Exception, e:
                mylog.exception ('Error %s downloading %s' % (str(e), x['url'],))
                image_ok = False
        
            if not image_ok:
                x['url'] = 'ERROR '+x['url'] # arruino la url para que no se reemplace en el html
        
    
        htmlpart.lastpart()


    # the feed section
    if rss_feed:
        subpart = writer.nextpart()
        subpart.addheader("Content-Transfer-Encoding", "quoted-printable")
        pout = subpart.startbody("text/plain", [("charset", 'us-ascii'), ("Name", "rss_feed.xml")])
        mimetools.encode(rssin, pout, 'quoted-printable')
        rssin.close()


    # Now that we're done, close our writer and
    # return the message body
    writer.lastpart()
    msg_source = out.getvalue()
    out.close()
    return email.message_from_string(msg_source.encode(encoding, 'replace'))


def createTextEmail(text, headers, encoding='utf-8'):
    t = '\r\n'.join([x+': '+y for x,y in headers])
    t += '\r\n\r\n'
    t += text
    return email.message_from_string(t.encode(encoding, 'replace'))
