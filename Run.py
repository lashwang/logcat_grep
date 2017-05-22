#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
#import fire
from logcat_grep import LogCatGrep
import os


class CLIAPI(object):
    def grep_logcat(self):
        LogCatGrep.parse_today()

def main():
    #fire.Fire(CLIAPI)
    CLIAPI().grep_logcat()


if __name__ == "__main__":
    main()