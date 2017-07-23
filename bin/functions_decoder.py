#!/usr/bin/python

__description__ = "Decoder Modules"
__author__="Gita Ziabari"
__version__="0.0.2"
__date__="07/22/2017"

"""
    This file is part of Yalda.

    Yalda is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    Yalda is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Yalda.  If not, see <http://www.gnu.org/licenses/>.
"""


import magic
import os, sys, re
import json
import email
import mimetypes
import shutil
import binascii
import glob
import mailbox
import base64
from Crypto.Cipher import XOR
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *
from functions_database import *

import random
import time


def parse_wsf_file(zip_file):
    domain_lst=[]
    severity = 2
    txt = open(zip_file, "r")
    lines = txt.readlines()
    txt.close()
    try:
      for line in lines:
           if not re.search("Array", line):
              continue
           list_array = line.split("Array(")

           array_data = ((list_array[1].split(";")[0]).strip(")")).split(",")
           severity = 4
           for i in array_data:
               domain =  i.strip('"')
               domain_lst.append(domain)
      return domain_lst, severity
    except:
       return domain_lst, severity


def parse_rtf_file(file_path):
    domain_lst = []
    severity = 1
    blob = open(file_path, 'r').read()
    string = ''.join(blob.splitlines())
    pattern = re.compile('68007400740070[\w\d]{,400}64006f0063')
    result = pattern.search(string)
    if result:
       severity = 5
       link = ''.join(binascii.unhexlify(str(result.group(0))).split('\x00'))
       domain = (get_short_url(link)).rstrip("/")
       if domain in domains_seen:
          return []
       domain_lst.append(domain)
    return domain_lst, severity


def parser_pdf_zero_day(file_path):
    domain_lst = []
    severity = 2
    blob = open(file_path, 'r').read()
    string = ''.join(blob.splitlines())
    match = re.search("/Type /Action/S /URI/URI \((http:\/\/[a-zA-Z_][a-zA-Z_0-9-./]*)\)\>\>endobj", string)
    if match:
          severity = 5
          link =  match.group(1)
          domain = (get_short_url(link)).rstrip("/")
          domain_lst.append(domain)
    return domain_lst, severity

def parser_pdf_embedded_java_script(file_path):
    domain_lst = []
    severity = 2
    blob = open(file_path, 'r').read()
    string = ''.join(blob.splitlines())
    match = re.search("OpenAction<</S/JavaScript", string)
    if match:
          severity = 3
    return domain_lst, severity


def parse_pdf_file(file_path):
    domain_lst, severity = parser_pdf_zero_day(file_path)
    domain_lst, severity = parser_pdf_embedded_java_script(file_path)
    return domain_lst, severity


def boolean_is_sakula(file_path):
    file_data = file_path
    # RE for 1.0 and 1.1
    re_pattern1 = r'([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})([ -~\x88]{100})(.{12}\x77\x77\x77\x77)'
    # RE for 1.2, 1.3, 1.4
    re_pattern2 = r'([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{50})([ -~]{12})(0uVVVVVV)'
    xor_data = xor_file(file_data, '\x88')
    config_list = re.findall(re_pattern1, xor_data)
    print config_list
    

def xor_file(file_data, key):
    cipher = XOR.new(key)
    return cipher.decrypt(file_data)
    
if __name__ == "__main__":
   print "hello world"
