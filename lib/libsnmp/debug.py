# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# Customised logging stuff

import logging
import os

class snmpLogger(logging.Logger):

    def __init__(self, name):
        pid = os.getpid()

        FORMAT = "%(asctime)s [" + str(pid) + "] %(levelname)7s - %(message)s"
        level = logging.DEBUG
        logging.Logger.__init__(self, name, level)

        handler = logging.StreamHandler()
        formatter = logging.Formatter(FORMAT)
        handler.setFormatter(formatter)
        self.addHandler(handler)
        return

logging.setLoggerClass(snmpLogger)
