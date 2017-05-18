#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
import fire
from logcat_grep import LogCatGrep
import os


class CLIAPI(object):
    def grep_logcat(self):
        dir_list = ["/usr/local/seven/usa-ap01/logs/","/usr/local/seven/usa-ap02/logs/"]
        print 'grep_logcat'
        for dir in dir_list:
            if os.path.exists(dir):
                LogCatGrep().parser_dir(dir)
                break


def main():
    fire.Fire(CLIAPI)


if __name__ == "__main__":
    main()