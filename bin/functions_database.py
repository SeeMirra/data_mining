#!/usr/local/bin/python

__description__ = "Insert or export data from mongodb database"
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

import os, sys, re
import pymongo
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
from pymongo import MongoClient

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *

client = MongoClient(localhost, port)
db = client[db_name]
yalda_collection = db[collection_name]


def insert_data_in_database(domain_lst, file_path, md5, file_type, size):
       time = get_iso_date_in_microseconds()
       data_tbl = {'IngestTime': time,
                   'file_path':file_path,
                   'md5': md5,
                   'size': size,
                   'source': "yalda_mining_data",
                   'file_type': file_type,
                   'Indicator': domain_lst}
       inserted_id = db.yalda_collection.insert_one(data_tbl)


def insert_file_detailed_info_in_database(file_info):
    time = get_iso_date_in_microseconds()
    file_info.setdefault('IngestTime', time)
    inserted_id = db.yalda_collection.insert_one(file_info)


def get_yalda_collection():
    domain_tbl = []
    search_tbl = [{'source': "yalda_mining_data"}]
    for data in db.yalda_collection.find({'$and' : search_tbl},  no_cursor_timeout=True):
       domain_lst = domain = data.get("Indicator")
       for domain in domain_lst:
           if domain not in domain_tbl:
              domain_tbl.append(domain)
    return domain_tbl 

def get_md5_attachments():
    md5_tbl = []
    search_tbl = [{'source': "yalda_mining_data"}]
    for data in db.yalda_collection.find({'$and' : search_tbl},  no_cursor_timeout=True):
        md5 = domain = data.get("md5")
        if md5 not in md5_tbl:
           md5_tbl.append(md5)
    return md5_tbl

def get_entrie_data_database():
    data_tbl = []
    search_tbl = [{'source': "yalda_mining_data"}]
    for data in db.yalda_collection.find({'$and' : search_tbl},  no_cursor_timeout=True):
        if data not in data_tbl:
           data_tbl.append(data)
    return data_tbl

def get_domain_yalda_mining_data():
    domain_tbl = []
    search_tbl = [ {'source': "yalda_mining_data",
                   }
                 ]
    try:
       for data in db.yalda_collection.find({'$and' : search_tbl},  no_cursor_timeout=True):
        domain_lst = data.get("Indicator")
        if domain_lst == []:
           continue
        domain_tbl+=domain_lst
       return domain_tbl
    except:
      return domain_tbl

def insert_strings_collection(strings_tbl):
    time = get_iso_date_in_microseconds()
    strings_tbl.setdefault('IngestTime', time)
    inserted_id = db.yalda_collection_sha1_strings.insert_one(strings_tbl)


def get_strings_collection1():
    data_tbl = []
    strings_dict = {}
    md5_lst = []
    search_tbl = [{"Source": "yalda_strings_collection"}]
    
    try:
       for data in db.yalda_collection_sha1_strings.find({'$and' :search_tbl},  no_cursor_timeout=True):
           strings_lst = data.get("Embedded_strings")
            
           md5 = data.get("MD5")
           if md5 in md5_lst:
              continue
           else:
              strings_dict.setdefault(md5, strings_lst)
              md5_lst.append(md5)
    except:
         return strings_dict      
    return strings_dict


def get_strings_collection():
    data_tbl = []
    strings_dict = {}
    md5_lst = []
    search_tbl = [{"Source": "yalda_strings_collection"}]

    query = db.yalda_collection_sha1_strings.find()
    for data in query:
           md5 = data.get("MD5")
           md5_lst.append(md5)
    return md5_lst



if __name__ == "__main__":
   aa = get_strings_collection()
   print aa
   print "Hello World!"
