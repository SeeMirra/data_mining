#!/usr/bin/python
from datetime import datetime,  timedelta
import os, sys, ihooks

def format_date_pack():
    lastHourDateTime = datetime.today() - timedelta(minutes = 1)
    return lastHourDateTime.strftime('%Y%m%dT%H%M')

def import_from(name):
    loader = ihooks.BasicModuleLoader()
    m = loader.find_module(name, sys.path)
    if not m:
        raise ImportError, name
    m = loader.load_module(name, m)
    return m

def command(command_string):
    stdout = os.popen (command_string)
    result = stdout.read()
    return result

def remove_file(file_path):
    if boolian_file_exist(file_path):
       os.remove(file_path)


def boolian_file_exist(file_name):
    file_exists = os.path.isfile(file_name)
    if  file_exists:
       return True
    return False

def get_yesterday():
    i = datetime.now() - timedelta(hours=24)
    date = ("%s-%02d-%02d" % (i.year, i.month, i.day))
    return date
