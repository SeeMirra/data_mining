#!/usr/local/bin/python
import pymongo
import datetime, sys, time

from pymongo import MongoClient
from functions_lib  import *

sys.path.append("../src/")
from config_file import *

client = MongoClient()
client = MongoClient(localhost, port)
db = client['zagros']
zagros_hashes = db["zagros_hashes"]
zagros_urls = db["zagros_urls"]

def insert_data(md5, mal_tbl, hash_type, sha256):
    time = get_iso_date_in_microseconds()
    boolean = bool_md5_exist_database(md5)
    if boolean:
       print md5+" already exists in the database"
       return
    malware_type = mal_tbl.get("type")
    malware_name = mal_tbl.get("name")
    severity = mal_tbl.get("severity")

    attr_tbl = {"malware_type": malware_type,
                "malware_name": malware_name,
                "hash_type": hash_type,
                "severity": severity}
    
    data_tbl = { "Type": "hash",
                 "sha256": sha256,
                 "Indicator": md5,
                 'IngestTime': time,
                 'Attributes': attr_tbl}
    db.zagros_hashes.insert_one(data_tbl)


def find_data(search_tbl):
    data = []
    for row in db.zagros_hashes.find({'$and' : search_tbl}):
        data.append(row)
    return data

def remove_data(md5):
    result = db.zagros_hashes.delete_one({'$and' : [{"Indicator":md5}]})
    result.deleted_count

def get_md5_lst():
    md5_tbl = []
    search_tbl = [{"Type": "hash"}]
    queries = find_data(search_tbl)
    for data in queries:
       md5 = data.get("Indicator")
       md5_tbl.append(md5)
    return md5_tbl

def bool_md5_exist_database(md5):
    boolean = False
    data = find_data([{"Indicator":md5}])
    if len(data)!=0:
       boolean=True
    return boolean


def insert_url_data(url):
    time = get_iso_date_in_microseconds()
    boolean = bool_url_exist_database(url)
    if boolean:
       print url+" exists in the database"
       return
    data_tbl = {"Type": "url",
                "URL": url,
                'IngestTime': time}
    db.zagros_urls.insert_one(data_tbl)

def find_url_data(search_tbl):
    data = []
    #for row in db.zagros_urls.find({'$and' : search_tbl}):
    for row in db.zagros_urls.find().sort("URL", pymongo.DESCENDING):
        data.append(row)
    return data

def get_url_lst():
    url_tbl = []
    search_tbl = [{"Type": "url"}]
    queries = find_url_data(search_tbl)
    for data in queries:
       url = data.get("URL")
       url_tbl.append(url)
    return url_tbl

def bool_url_exist_database(url):
    boolean = False
    data = find_data([{"URL":url}])
    if len(data)!=0:
       boolean=True
    return boolean

def remove_url_data(url):
    result = db.zagros_urls.delete_one({'$and' : [{"URL":url}]})
    result.deleted_count 


if __name__ == '__main__':
   url = "cbatlantaautoinjuryattorneys.com"
   #remove_url_data(url)
   aa=  get_url_lst()
print aa
