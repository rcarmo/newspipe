def ReadConfig():
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-i", "--inifile", dest="inifile", help=".ini file with the configuration")
    parser.add_option("-o", "--opml", dest="opml", help="the filename or URL of the OPML file with the list of feeds to check")
    parser.add_option("-s", "--smtp_server", dest="smtp_server", help="fully qualified domain name or IP address of the SMTP server to send messages through")
    parser.add_option("-e", "--sender", dest="sender", help="optional e-mail address to use as From: - overrides the OPML ownerEmail field.")
    parser.add_option("-t", "--textonly", action="store_const", const="1", dest="textonly", help=" all the messages sent by newspipe will be sent in plaintext format, without any HTML")
    parser.add_option("-l", "--log_console", action="store_const", const="1", dest="log_console", help="send logging output to the console and to the log file.")
    parser.add_option("-c", "--check_online", dest="check_online", help="URL of a webpage that the program will try to fetch to determine if there is a network connection available")
    parser.add_option("-d", "--sleep_time", dest="sleep_time", help="Number of minutes to wait before re-checking feeds")
    parser.add_option("-b", "--batch", action="store_const", const="0", dest="sleep_time", help="process all feeds and exit inmediatly")
    parser.add_option("-f", "--offline", action="store_const", const="1", dest="offline", help="the program won't try to fetch any data from the internet, using cached versions instead")
    parser.add_option("-x", "--debug", action="store_const", const="1", dest="debug", help="log a lot of debug information")
    parser.add_option("-w", "--workers", dest="workers", help="Number of threads to use simultaneusly")
    parser.add_option("-m", "--multipart", action="store_const", const="on", dest="multipart", help=" include a plaintext version of item contents as well as an HTML version.")
    parser.add_option("-p", "--can_pipe", action="store_const", const="1", dest="can_pipe", help="Allow the pipe:// protocol in urls")
    parser.add_option("-u", "--encoding", dest="encoding", help="unicode encoding to use when composing the emails")
    parser.add_option("-r", "--proxy", dest="proxy", help="addess and port of the proxy server to use")
    parser.add_option("-a", "--threading", action="store_const", const="1", dest="threading", help="include threading headers in the emails")
    parser.add_option("", "--subject", dest="subject", help="add a fixed text to the subject of every message")
    parser.add_option("", "--smtp_authentication", action="store_const", const="0", dest="smtp_auth", help="authenticate with SMTP server")
    parser.add_option("", "--smtp_auth_user", dest="smtp_user", help="SMTP username used for authentication")
    parser.add_option("", "--smtp_auth_pass", dest="smtp_pass", help="SMTP password used for authentication")
    parser.add_option("", "--send_method", dest="send_method", help="Method used to send the resulting emails. Possible values: SMTP, PROCMAIL, BOTH")
    parser.add_option("", "--procmail", dest="procmail", help="Path of the procmail script, used when SEND_METHOD=PROCMAIL or BOTH")
    parser.add_option("", "--reverse", action="store_const", const="1", dest="reverse", help="reverse the order of emails as they are sent")


    (options, args) = parser.parse_args()

    if options.inifile:
        inifile = options.inifile
    else:
        source_path = os.path.split(sys.argv[0])[0]

        for p in ('.', source_path):
            inifile = os.path.join(p, 'newspipe.ini')
            if os.path.exists(inifile):
                break

    if not os.path.exists(inifile):
        raise ValueError ("Can't find the ini file at "+inifile)

    ini = ConfigParser.ConfigParser()
    ini.read(inifile)

    result = {}
    for attr in ini.options('NewsPipe'):
        result[attr.lower()] = ini.get('NewsPipe', attr)


    for key, value in CONFIG_DEFAULTS.items():
        if not key in result.keys():
            result[key] = value

    for key in [x.dest for x in parser.option_list]:
        if key:
            value = getattr(options, key)
            if value:
                result[key] = value

    if result['proxy']:
        if not '://' in result['proxy']:
            result['proxy'] = 'http://' + result['proxy']
        proxy_support = urllib2.ProxyHandler({"http":result['proxy']})
        opener = urllib2.build_opener(proxy_support)
        urllib2.install_opener(opener)

    if not (result['send_method'].lower() in ('smtp', 'procmail', 'both')):
        raise ValueError ('The value of the parameter SEND_METHOD must be SMTP, PROCMAIL or BOTH')

    return result