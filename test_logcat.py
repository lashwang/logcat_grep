import unittest2
import sys
import os
from datetime import datetime, timedelta
from io import BytesIO
import zlib
import arrow
from logcat_grep import *



class MyTestCase(unittest2.TestCase):

    @unittest2.skip("skip")
    def test_something(self):
        LogCatGrep().parse_file('test.bin',if_test = True)

    def test_parse_dir(self):
        LogCatGrep.parse_today(True)






if __name__ == '__main__':
    unittest2.main()
