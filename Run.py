#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
import fire
from logcat_grep import LogCatGrep
import os


class CLIAPI(object):
    def grep_logcat(self):
        dir_list = ["/usr/local/seven/usa-ap01/logs/flume/","/usr/local/seven/usa-ap02/logs/flume/"]
        for dir in dir_list:
            if os.path.exists(dir):
                print 'start parsing dir'
                LogCatGrep().parser_dir(dir)
                break


def main():
    #fire.Fire(CLIAPI)
    CLIAPI.grep_logcat()


if __name__ == "__main__":
    main()