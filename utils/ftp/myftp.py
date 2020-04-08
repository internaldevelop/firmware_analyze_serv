import sys
import os
import time
from ftplib import *

_XFER_FILE = 'FILE'
_XFER_DIR = 'DIR'
_XFER_NONE = "NONE"


class Xfer(object):
    '''
    @note: upload local file or dirs recursively to ftp server
    '''

    def __init__(self):
        self.ftp = None

    def __del__(self):
        pass

    def setFtpParams(self, ip, uname, pwd, port=21, timeout=60):
        self.ip = ip
        self.uname = uname
        self.pwd = pwd
        self.port = port
        self.timeout = timeout

    def initEnv(self):
        if self.ftp is None:
            self.ftp = FTP()
            print
            '### connect ftp server: %s ...' % self.ip
            if sys.version_info < (2, 7, 0):
                self.ftp.connect(self.ip, self.port)
            else:
                self.ftp.connect(self.ip, self.port, self.timeout)
            self.ftp.login(self.uname, self.pwd)
            print
            self.ftp.getwelcome()

    def clearEnv(self):
        if self.ftp:
            self.ftp.close()
            print
            '### disconnect ftp server: %s!' % self.ip
            self.ftp = None

    def isExist(self, remotepath):
        '''
        if remoetepath exists,
            return TRUE and the type of remotepath, FILE or DIR
        else
            return (FALSE, NONE)
        '''

        def parse(line):
            pass

        bExist = False
        if self.ftp:
            try:
                self.ftp.dir(remotepath, parse)
                bExist = True
            except:
                pass

        if bExist:
            res = self.ftp.nlst(remotepath)
            if len(res) == 0 or len(res) > 1 or len(res[0]) > len(remotepath):
                return True, _XFER_DIR
            return True, _XFER_FILE

        return False, _XFER_NONE

    def uploadFile(self, localpath, remotepath=None):
        '''
        @note: assume localpath is 'c:\log.txt' and remotepath is '/xx/log.txt',
               then  /xx dir must exists
        '''
        if not os.path.isfile(localpath):
            sys.stderr.write("--- %r doesn't exist" % localpath)
            return

        if remotepath:
            index = remotepath.rfind('\\')
            if index == -1:
                index = remotepath.rfind('/')

            if index != -1:
                basedir = remotepath[:index]
                bExist, sType = self.isExist(basedir)
                if not bExist or sType != _XFER_DIR:
                    sys.stderr.write("--- %r doesn't exist" % basedir)
                    return

        curdir = ""
        if not remotepath.startswith("/"):
            curdir = self.ftp.pwd()
            if not curdir.endswith("/"):
                curdir += '/'

        print
        '+++ upload %s to %s:%s%s' % (localpath, self.ip, curdir, remotepath)
        self.ftp.storbinary('STOR ' + remotepath, open(localpath, 'rb'))

    def uploadDir(self, localdir='./', remotedir='./'):
        if not os.path.isdir(localdir):
            sys.stderr.write("--- %r doesn't exist" % localdir)
            return
        if not remotedir.endswith('/'):
            remotedir += '/'

        # if remotedir doesn't exist, create one
        try:
            def parse(line):
                pass

            self.ftp.dir(remotedir, parse)
        except:
            self.ftp.mkd(remotedir)

        curdir = self.ftp.pwd()

        self.ftp.cwd(remotedir)
        for file in os.listdir(localdir):
            src = os.path.join(localdir, file)
            if os.path.isfile(src):
                self.uploadFile(src, file)

            elif os.path.isdir(src):
                bExist, sType = self.isExist(file)
                if not bExist:
                    self.ftp.mkd(file)
                elif sType != _XFER_DIR:
                    sys.stderr.write('--- file %r exists, not a directory' % file)
                    continue
                self.uploadDir(src, remotedir + file)

        self.ftp.cwd(curdir)

    def downloadFile(self, remotepath, localDir):
        curdir = self.ftp.pwd()
        if not curdir.endswith('/'):
            curdir += '/'
        if not remotepath.startswith("/"):
            remotepath = curdir + remotepath

        bExist, sType = self.isExist(remotepath)
        if not bExist:
            sys.stderr.write("--- %r:%r doesn't exist" % (self.ip, remotepath))
            return

        if sType != _XFER_FILE:
            sys.stderr.write("--- %r:%r is not a file" % (self.ip, remotepath))
            return

        if not os.path.isdir(localDir):
            sys.stderr.write("--- %r doesn't exist" % localDir)
            return

        if not localDir.endswith("/") and not localDir.endswith("\\"):
            localDir = localDir + '/'

        temp = remotepath.split("/")
        filename = temp[len(temp) - 1]
        dst = localDir + filename

        remotedir = remotepath[:remotepath.rfind(filename)]

        self.ftp.cwd(remotedir)

        f = open(dst, "wb")
        print
        "+++ download %r:%r to %s" % (self.ip, remotepath, dst)
        self.ftp.retrbinary("RETR %s" % filename, f.write)
        f.close()

        self.ftp.cwd(curdir)

        return True

    def downloadDir(self, remoteDir, localDir):
        if not os.path.isdir(localDir):
            os.mkdir(localDir)
        if not localDir.endswith("/") and not localDir.endswith("\\"):
            localDir = localDir + '/'

        bExist, sType = self.isExist(remoteDir)
        if not bExist:
            sys.stderr.write("--- %r:%r doesn't exist" % (self.ip, remoteDir))
            return

        if sType != _XFER_DIR:
            sys.stderr.write("--- %r:%r is not a dir" % (self.ip, remoteDir))
            return

        curdir = self.ftp.pwd()
        if not curdir.endswith('/'):
            curdir += '/'
        if not remoteDir.startswith("/"):
            remoteDir = curdir + remoteDir
        if not remoteDir.endswith("/"):
            remoteDir = remoteDir + '/'

        for file in self.ftp.nlst(remoteDir):
            bExist, sType = self.isExist(file)
            if not bExist:
                sys.stderr.write("--- %r:%r doesn't exist" % (self.ip, file))
                return

            if sType == _XFER_DIR:
                temp = file.split("/")
                filename = temp[len(temp) - 1]

                self.downloadDir(file, localDir + filename)
                continue

            self.downloadFile(file, localDir)
