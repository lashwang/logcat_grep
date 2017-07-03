import unittest2
import sys
import os
from datetime import datetime, timedelta
from io import BytesIO
import zlib
import arrow
from logcat_grep import *



class MyTestCase(unittest2.TestCase):

    def test_something(self):
        LogCatGrep().parse_file('test.bin',if_test=True)

    def test_parse_dir(self):
        LogCatGrep.parse_today(True)

    def test_version_code(self):
        line = "06-27 23:46:02.710  6350  6669 E [Native]OCEngine: 06-27 23:46:02.710 +0200 6669 [E] [oc_backtrace.cpp:76] (-2) - dumpping backtrace for client:700504862\n"
        ver = LogCatGrep().get_version_code(line)
        print ver



if __name__ == '__main__':
    unittest2.main()
