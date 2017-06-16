#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
import requests
import pandas as pd
from bs4 import BeautifulSoup


logger = logging.getLogger(__name__)



class ObjFinder(object):

    URL = 'http://10.10.10.22:8080/job/adclear_2_0/'
    URL_BASE = 'http://10.10.10.22:8080'

    def __init__(self,version_code = 0):
        self.version_code = version_code



    def sync_from_server(self):
        try:
            r = requests.get(self.__class__.URL)
            self.parse_jenkins_main_page(r.content)
        except Exception,error:
            print error



    def parse_jenkins_main_page(self,content):
        html = BeautifulSoup(markup=content, features='lxml')

        all = html.find(id='buildHistory').find_all(class_="build-row no-wrap ")

        for item in all:
            url = item.find(class_="tip model-link inside").attrs['href']
            url = self.__class__.URL_BASE + url
            build_number = url.split('/')[-2]
            try:
                version_code = self.parse_version_code(url)
            except Exception:
                continue
            print build_number,version_code



    def parse_version_code(self, url):
        r = requests.get(url)
        html = BeautifulSoup(markup=r.content, features='lxml')

        all_lines = html.find(class_="fileList").find_all('tr')

        if len(all_lines) != 5:
            raise ValueError

        apk_name = all_lines[0].find_all('td')[1].text
        version_code = apk_name.split('_')[4]
        version_code = version_code.replace('.','')

        return version_code

