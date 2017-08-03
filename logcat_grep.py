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
import time
import re



OUTPUT_DIR = 'output'

RECIPIENTS = ['swang@seven.com','ahu@seven.com','fluo@seven.com','jinwang@seven.com',
              'kyang@seven.com','wli@seven.com',
              'dmorgan@seven.com','sglazova@seven.com','cadams@seven.com']
RECIPIENTS_TEST = ['swang@seven.com']




KEY_WORD = "sig_handler signal: "
KEY_WORD_VERSION_CODE = "dumpping backtrace for client:"
VERSION_CODE_BEGIN = 700505300

#KEY_WORD = "send CTQD error"
KEY_WORD_REMOVE = "sig_init"

LOGCAT_BEFORE_LINE = 500
LOGCAT_AFTER_LINE = 50



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




class LogCatGrep(object):
    def __init__(self):
        self.on_parse_started()
        self.skip_user_list = set()
        self.user_info = dict()
        self.back_trace_line = list()

    def on_parse_started(self):
        shutil.rmtree(OUTPUT_DIR, ignore_errors=True)

        try:
            os.mkdir(OUTPUT_DIR)
        except Exception, error:
            print error

        self.time_str = arrow.now().format('MM_DD_HH_mm_ss')
        self.curr_version_code = 0

    def send_email(self,grep_filename, if_test, grep_info):
        # zip the output file
        path = 'output'
        now = arrow.now()
        zip_file = 'output/output_{}.zip'.format(self.time_str)

        myzip = ZipFile(zip_file, 'w')
        for f in listdir(path):
            if isfile(join(path, f)) and os.path.splitext(f)[1] == '.log':
                f = os.path.join(path, f)
                myzip.write(f)

        myzip.close()

        subject = 'Logcat Crash Report'
        content = 'Logcat Crash Report in file {} for key:{}\n'.format(grep_filename, KEY_WORD)



        summery = "\n"

        for k in grep_info.user_info.keys():
            summery += "{}:{}\n".format(k, grep_info.user_info[k])

        content += summery

        back_trace = '\n\n\n\n\n\nBacktrace logs:\n'
        back_trace += ''.join(self.back_trace_line)
        content += back_trace

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

    def get_version_code(self,line):
        result = re.match("(.+)dumpping backtrace for client:(\d+)", line)
        if result:
            return int(result.group(2))

        return 0


    def find_useful_crash(self):
        return self.curr_version_code >= VERSION_CODE_BEGIN


    def on_file_readed(self,io, pckuserId, date):
        find = False
        find_number = 0
        alllines = io.readlines()
        filename = '{}/{}.log'.format(OUTPUT_DIR, pckuserId)
        all_filename = '{}/{}.log'.format(OUTPUT_DIR, self.time_str)
        skip_lines = 0
        for line_number, line in enumerate(alllines):

            if 'oc_backtrace.cpp' in line:
                if self.find_useful_crash():
                    self.back_trace_line.append(line)
                    if not "\n" in line:
                        self.back_trace_line.append('\n')

            if skip_lines > 0:
                skip_lines = skip_lines - 1
                continue

            if KEY_WORD_VERSION_CODE in line:
                self.curr_version_code = self.get_version_code(line)
                #print "get version code :" + str(self.curr_version_code)
                if self.find_useful_crash():
                    print "find crash for version {} in user {}".format(str(self.curr_version_code),pckuserId)
                    self.back_trace_line.append('\n\n')
                    self.back_trace_line.append("[UserID]:{}\n".format(pckuserId))
                    self.back_trace_line.append(line)
                    f_all = open(all_filename, 'a')
                    find = True
                    f_all.write(
                        "[crash find for user, dump logs]{}\n====================================\n".format(pckuserId))
                    start = line_number - LOGCAT_BEFORE_LINE
                    end = line_number + LOGCAT_AFTER_LINE
                    if start < 0:
                        start = 0
                    # f.write("".join(alllines[start:end]))
                    f_all.write("".join(alllines[start:line_number]))
                    f_all.write("\n[UserID]:{}\n".format(pckuserId))
                    f_all.write("".join(alllines[line_number:end]))

                    # f.close()
                    f_all.close()
                    skip_lines = LOGCAT_AFTER_LINE
                    find_number = find_number + 1
                continue


                            # if KEY_WORD in line:
            #     # f = open(filename, 'a')
            #     self.back_trace_line.append('\n\n')
            #     self.back_trace_line.append("[UserID]:{}\n".format(pckuserId))
            #     self.back_trace_line.append(line)
            #     f_all = open(all_filename, 'a')
            #     find = True
            #     f_all.write("[crash find for user, dump logs]{}\n====================================\n".format(pckuserId))
            #     start = line_number - LOGCAT_BEFORE_LINE
            #     end = line_number + LOGCAT_AFTER_LINE
            #     if start < 0:
            #         start = 0
            #     # f.write("".join(alllines[start:end]))
            #     f_all.write("".join(alllines[start:line_number]))
            #     f_all.write("\n[UserID]:{}\n".format(pckuserId))
            #     f_all.write("".join(alllines[line_number:end]))
            #
            #     # f.close()
            #     f_all.close()
            #     skip_lines = LOGCAT_AFTER_LINE
            #     find_number = find_number + 1



        return find_number

    def parse_dir(self, path, start_date = FILE_TIME_START, end_date = FILE_TIME_END, if_test = False):
        print 'start parsing dir,start date:{}, end_date:{}'.format(start_date, end_date)
        for f in listdir(path):
            if isfile(join(path, f)):
                self.parse_file_by_date(join(path, f),start_date,end_date,if_test)

    @staticmethod
    def parse_log_server(start_date = FILE_TIME_START, end_date = FILE_TIME_END,if_test = False):
        dir_list = ["/usr/local/seven/usa-ap01/logs/flume/", "/usr/local/seven/usa-ap02/logs/flume/"]
        for dir in dir_list:
            if os.path.exists(dir):
                print 'start parsing dir:{}'.format(dir)
                LogCatGrep().parse_dir(dir,start_date,end_date,if_test)
                break

    @staticmethod
    def parse_today(if_test = False):
        now = arrow.utcnow()
        yesterday = now.replace(days=-1)

        LogCatGrep.parse_log_server(yesterday.format('YYYY-MM-DD'),
                                    now.format('YYYY-MM-DD'),
                                    if_test)



    def parse_file_by_date(self,aggregated_log_file,start_date = FILE_TIME_START,end_date = FILE_TIME_END,if_test=False):
        last_modified_time = arrow.get(os.path.getmtime(aggregated_log_file)).format('YYYY-MM-DD')
        if (last_modified_time < start_date or last_modified_time >= end_date):
            print 'skip file {}'.format(aggregated_log_file)
            return
        print 'start parsing file {}, last modified time {}'.format(aggregated_log_file, last_modified_time)
        self.parse_file(aggregated_log_file,if_test)

    def parse_file(self,aggregated_log_file,if_test=False):
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
                        is_beta = False

                        # for line in payload_data.split("\n")[0:100]:
                        #     if '[Native]' in line and '[D]' in line:
                        #         is_beta = True
                        #         break
                        #
                        # if not is_beta:
                        #     self.skip_user_list.add(pckuserId)
                        #     continue
                        #
                        # if 'oc_backtrace.cpp' not in payload_data:
                        #     continue

                        find_number = self.on_file_readed(StringIO.StringIO(payload_data),
                                            pckuserId,
                                            arrow.get(pck_start_time).format('YYYY-MM-DD-HH:mm'))
                        find = (find or find_number >= 1)

                        if find_number >= 1:
                            if pckuserId in self.user_info.keys():
                                self.user_info[pckuserId] = self.user_info[pckuserId] + find_number
                            else:
                                self.user_info[pckuserId] = find_number

                        self.curr_version_code = 0
                    except Exception,error:
                        print error

                finally:
                    payload.close()
            # end while

        finally:
            binaryFile.close()
        # end try:


        if find:
            print 'find crash for file {}'.format(aggregated_log_file)
            self.send_email(aggregated_log_file,if_test,self)
            #time.sleep(1)
            self.user_info = dict()
            self.back_trace_line = list()
            self.on_parse_started()


