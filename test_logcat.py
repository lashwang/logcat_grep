import unittest2
import sys
import os
from datetime import datetime, timedelta
from io import BytesIO
import zlib
import arrow
from logcat_grep import *



class MyTestCase(unittest2.TestCase):

    @unittest2.skip('skip')
    def test_something(self):
        LogCatGrep().parse_file('aggregated0.2017-04-11T204702.402')

    def test_parse_dir(self):
        LogCatGrep().parser_dir('.')




if __name__ == '__main__':
    unittest2.main()
