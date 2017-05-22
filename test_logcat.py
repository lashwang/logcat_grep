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
        LogCatGrep().parse_file('test.bin',if_test = True)

    @unittest2.skip('skip')
    def test_parse_dir(self):
        LogCatGrep().parser_dir('.')




if __name__ == '__main__':
    unittest2.main()
