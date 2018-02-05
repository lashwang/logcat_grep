#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
#import fire
from logcat_grep_cpu import LogCatGrepCPU
import os


class CLIAPI(object):
    def grep_logcat(self):
        LogCatGrepCPU.parse_today()

def main():
    #fire.Fire(CLIAPI)
    CLIAPI().grep_logcat()


if __name__ == "__main__":
    main()