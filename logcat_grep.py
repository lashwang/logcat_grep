#!/usr/bin/python
# -*- coding: utf-8 -*-


import unittest2
import sys
import os
from datetime import datetime, timedelta
from io import BytesIO
import zlib
import arrow
import StringIO
import shutil
from os import listdir
from os.path import isfile, join
import smtplib
import traceback
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from zipfile import ZipFile
from Email import Email
from itertools import islice



OUTPUT_DIR = 'output'

RECIPIENTS = ['swang@seven.com','wli@seven.com','ahu@seven.com','kyang@seven.com','fluo@seven.com']
RECIPIENTS_TEST = ['swang@seven.com']




KEY_WORD = "sig_handler signal: 11"
KEY_WORD_REMOVE = "sig_init"

LOGCAT_BEFORE_LINE = 100
LOGCAT_AFTER_LINE = 10



FILE_TIME_START = '2017-05-05'
FILE_TIME_END = '2017-05-06'


DATETIME_FORMAT_DEFAULT = "%Y-%m-%d %H:%M:%S"
DATETIME_FORMAT_IN_FILENAME = "%Y-%m-%dT%HC%MC%S"
DATE_FORMAT = "%Y-%m-%d"

LOGS_TYPE_CRCS = 3
LOGS_TYPE_CRCS_EXTRA = 5
LOGS_TYPE_GUDS = 91
LOGS_TYPE_TERRA_UPC = 92
LOGS_TYPE_OTHERS = 99
LOGS_TYPE_INFO_ONLY = 100 # Only get aggregated file index
LOGS_TYPES = {0:{'name':'logcat',
                 'suffix':'.log'},
              1:{'name':'tcpdump',
                 'suffix':'.pcap'},
              2:{'name':'iptables',
                 'suffix':'.log'},
              3:{'name':'crcs',
                 'suffix':'.avro'},
              4:{'name':'qoe',
                 'suffix':'.log'},
              5:{'name':'crcs',
                 'suffix':'.avro'},
              LOGS_TYPE_GUDS:{'name':'guds',
                  'suffix':'.log'},
              LOGS_TYPE_TERRA_UPC:{'name':'crcs',
                 'suffix':'.avro'},
              LOGS_TYPE_OTHERS:{'name':'others',
                  'suffix':'.log'},
              LOGS_TYPE_INFO_ONLY:{'name':'info',
                  'suffix':'.info'}
            }

def toInt(bytesArr, pos, length):
    if len(bytesArr) < (pos + length):
        # sys.exit(-1)
        raise ValueError

    ret = 0
    offset = 0
    while True:
        if offset == 4 or offset == length: break
        ret = ret << 8 | ord(bytesArr[pos + offset])
        offset = offset + 1

    return ret

def toClientAddr(bytesArr, pos):
    nocIdInstanceId = toInt(bytesArr, pos, 4)
    nocId = nocIdInstanceId >> 8
    instanceId = nocIdInstanceId & 0x00ff
    hostId = toInt(bytesArr, pos + 4, 4)

    nocStr = str(hex(nocId)).replace('0x', "")
    hostStr = str(hex(hostId)).replace('0x', "")
    instanceStr = str(hex(instanceId)).replace('0x', "")
    return nocStr + "-" + hostStr + "-" + instanceStr

def toClientAddrHash(bytesArr):
    pckuserId = bytesArr.decode("utf-8")
    i = pckuserId.find(b"\x00")
    if i <= 0:
        return pckuserId
    else:
        return pckuserId[0:i]


def on_parse_started():
    shutil.rmtree(OUTPUT_DIR,ignore_errors=True)

    try:
        os.mkdir(OUTPUT_DIR)
    except Exception,error:
        print error


def on_file_readed(io,pckuserId,date):
    find = False
    find_number = 0
    alllines = io.readlines()
    filename = '{}/{}.log'.format(OUTPUT_DIR,pckuserId)

    skip_lines = 0
    for line_number, line in enumerate(alllines):
        if skip_lines > 0:
            skip_lines = skip_lines - 1
            continue
        if KEY_WORD in line:
            f = open(filename, 'a')
            find = True
            f.write("[crash find for user, dump logs]{}\n".format(pckuserId))
            start = line_number-LOGCAT_BEFORE_LINE
            end = line_number+LOGCAT_AFTER_LINE
            if start < 0:
                start = 0
            f.write("".join(alllines[start:end]))
            f.close()
            skip_lines = LOGCAT_AFTER_LINE
            find_number = find_number + 1



    return find_number

def send_email(grep_filename,if_test,grep_info):
    # zip the output file
    path = 'output'
    zip_file = 'output/output.zip'
    for f in listdir(path):
        if isfile(join(path, f)):
            f = os.path.join(path, f)
            with ZipFile(zip_file, 'w') as myzip:
                myzip.write(f)

    subject = 'Logcat Grep Result From {} to {}'.format(FILE_TIME_START, FILE_TIME_END)
    content = 'Logcat Grep Result from {} to {} for key:{}'.format(FILE_TIME_START, FILE_TIME_END, KEY_WORD)

    summery = "\n"

    for k in grep_info.user_info.keys():
        summery += "{}:{}\n".format(k,grep_info.user_info[k])

    content += summery


    email = Email()
    if if_test:
        email.send(RECIPIENTS_TEST,
                   subject,
                   content,
                   [zip_file])
    else:
        email.send(RECIPIENTS,
                   subject,
                   content,
                   [zip_file])



class LogCatGrep(object):
    def __init__(self):
        self.on_file_readed = on_file_readed
        on_parse_started()
        self.skip_user_list = set()
        self.user_info = dict()


    def parser_dir(self,path):
        print path
        for f in listdir(path):
            if isfile(join(path, f)):
                self.parse_file(join(path, f))




    def parse_file(self,aggregated_log_file,if_test = False):
        last_modified_time = arrow.get(os.path.getmtime(aggregated_log_file)).format('YYYY-MM-DD')
        print 'start parsing file {}, last modified time {}'.format(aggregated_log_file,last_modified_time)
        if if_test == False and (last_modified_time < FILE_TIME_START or last_modified_time >= FILE_TIME_END):
            print 'skip the file'
            return
        find = False
        binaryFile = open(aggregated_log_file, 'rb')
        try:
            total_size = os.path.getsize(aggregated_log_file)
            next_position = 0
            block_index = 0
            while True:
                blockhead = binaryFile.read(5)  # read block head
                if not blockhead:
                    print 'not header'
                    break
                pck_size = toInt(blockhead, 0, 4)
                ver = toInt(blockhead, 4, 1)
                if ver > 2:
                    break
                if ver == 1:
                    addrs_data = binaryFile.read(8)
                    pckuserId = toClientAddr(addrs_data, 0)
                elif ver == 2:
                    user_id_bytes = binaryFile.read(128)
                    pckuserId = toClientAddrHash(user_id_bytes)
                blockhead = binaryFile.read(15)
                next_pos = 0
                pck_log_type = toInt(blockhead, next_pos, 1)
                next_pos += 1
                pck_log_level = toInt(blockhead, next_pos, 2)
                next_pos += 2
                pck_start_time = toInt(blockhead, next_pos, 4)
                next_pos += 4
                pck_end_time = toInt(blockhead, next_pos, 4)
                next_pos += 4
                pckPayloadSize = toInt(blockhead, next_pos, 4)
                next_pos += 4
                next_position += pck_size
                if not (pckPayloadSize > 0):
                    print ("the log with invliad ver found!  version:%d ===> exit" % (ver))
                    break
                if next_position > total_size:
                    print (
                        "Block [%d] payload_data is not complete, next_position %d > total_size %d. aggregated_log_file is %s" \
                        % (block_index, next_position, total_size, aggregated_log_file))
                    break
                block_index += 1
                log_tpype_info = LOGS_TYPES.get(pck_log_type)
                if pck_log_type != 0:
                    #print ("pck_log_type %d is NOT supported" % pck_log_type)
                    binaryFile.seek(pckPayloadSize, 1)
                    continue

                if pckuserId in self.skip_user_list:
                    binaryFile.seek(pckPayloadSize, 1)
                    continue

                if pckuserId in self.user_info.keys() and self.user_info[pckuserId] >= 20:
                    print 'user {} crash number over 20. skip'.format(pckuserId)
                    binaryFile.seek(pckPayloadSize, 1)
                    continue

                bytesNeedsToWrite = pckPayloadSize
                payload = BytesIO()
                try:
                    while bytesNeedsToWrite > 0:
                        curLen = 5120
                        if bytesNeedsToWrite < 5120: curLen = bytesNeedsToWrite
                        blockBody = binaryFile.read(curLen)  # 5M  per writing
                        payload.write(blockBody)
                        bytesNeedsToWrite = bytesNeedsToWrite - curLen
                    # end while


                    try:
                        payload_data = zlib.decompress(payload.getvalue(), zlib.MAX_WBITS | 16)
                        if '[D]' not in payload_data:
                            print 'user {} is not in beta,skip this user'.format(pckuserId)
                            self.skip_user_list.add(pckuserId)
                            continue
                        find_number = self.on_file_readed(StringIO.StringIO(payload_data),
                                            pckuserId,
                                            arrow.get(pck_start_time).format('YYYY-MM-DD-HH:mm'))
                        find = (find or find_number >= 1)

                        if find_number >= 1:
                            if pckuserId in self.user_info.keys():
                                self.user_info[pckuserId] = self.user_info[pckuserId] + find_number
                            else:
                                self.user_info[pckuserId] = find_number
                    except Exception,error:
                        print error

                finally:
                    payload.close()
            # end while

        finally:
            binaryFile.close()
        # end try:


        if find:
            send_email(aggregated_log_file,if_test,self)


