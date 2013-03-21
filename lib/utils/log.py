import os, sys
import logging
import logging.handlers

class MyLog:
    debug_memory = 0 # include memory information in debug
    cache = 2        # keep mem stats for "cache" seconds

    h = None         # file handler
    result = None    # memory string
    lasttime = None  # last access to the file

    #def die(self): self.h.close()

    def memory(self):
        # /proc/self/status is only available on Linux)
        if self.debug_memory and sys.platform.lower().startswith('linux2'):
            if not self.lasttime:
                self.lasttime = time.time() - self.cache - 1
            if self.lasttime + self.cache >= time.time():
                return self.result

            if not self.h:
                self.h=file("/proc/self/status")
            else:
                self.h.seek(0)
            x=self.h.read(1024)
            result = ""
            for l in x.split("\n"):
                if l[0:2] != "Vm": continue
                l = l.replace(" kB", "")
                l = l.replace(" ", "")
                l = l.replace("\t", "")
                l = l.replace(":", ": ")
                result = result + l + ","
        
            if len(result) > 1:
                self.result = result
                result = result[:-1]
            else:
                result = self.result
            result = "[" + result + "] "
            return result
        else:
          return ''
    


    def debug(self, msg, *args, **kwargs):
        msg = self.memory() + msg
        self.log.debug(msg, *args, **kwargs)
    def info(self, msg, *args, **kwargs):
        msg = self.memory() + msg
        self.log.info(msg, *args, **kwargs)
    def warning(self, msg, *args, **kwargs):
        msg = self.memory() + msg
        self.log.warning(msg, *args, **kwargs)
    def exception(self, msg, *args, **kwargs):
        msg = self.memory() + msg
        self.log.exception(msg, *args, **kwargs)
    def error(self, msg, *args, **kwargs):
        msg = self.memory() + msg
        self.log.error(msg, *args, **kwargs)


    def logFile(self, stderr=True, name='default', location='.', debug=False):
        if not os.path.exists(location):
            os.makedirs(location)

        logger = logging.getLogger(name)
        hdlr = logging.handlers.RotatingFileHandler(os.path.join(location, name+'.log'), maxBytes=1024*500, backupCount=10)
        formatter = logging.Formatter('%(asctime)s %(thread)d %(levelname)-10s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)

        if stderr:
            hdlr = logging.StreamHandler(sys.stderr)
            hdlr.setFormatter(formatter)
            logger.addHandler(hdlr)


        if debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)


        self.log = logger


mylog = MyLog()
