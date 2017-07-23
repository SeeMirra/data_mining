#!/usr/bin/python
__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""

from datetime import datetime,  timedelta
import os, sys, ihooks
import hashlib
from stat import *
import zipfile
import shutil
import re
import magic
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

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

def get_md5sum(file_path):
    hash_md5 = None
    if os.path.exists(file_path):
       hash_md5 = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    return hash_md5

def get_sha256(file_path):
    hash_lib = None
    if os.path.exists(file_path):
       hash_sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    return hash_sha256

def get_sha1(file_path):
    hash_lib = None
    if os.path.exists(file_path):
       hash_sha1 = hashlib.sha1(open(file_path, "rb").read()).hexdigest()
    return hash_sha1

def remove_file(file_path):
    if boolian_file_exist(file_path):
       os.remove(file_path)


def boolian_file_exist(file_name):
    file_exists = os.path.isfile(file_name)
    if  file_exists:
       return True
    return False

def get_today():
    i = datetime.now()
    date = ("%s-%02d-%02d" % (i.year, i.month, i.day))
    return date

def get_embedded_objects_run_foremost(filepath, mime_attachment_directory):
    today = get_today()
    extracted_files_lst = []
    random = get_random()
    output_dir = None
    try:
        dir_name =  os.path.dirname(filepath)
        filename = os.path.basename(filepath).strip(".")
        output_dir = mime_attachment_directory+"/"+random+"_"+today
        md5 = get_md5sum(filepath)
        command("foremost -i "+filepath+" -o "+output_dir +"  &> /dev/null")
        file_lst =  walktree(output_dir)
        for extracted_file in file_lst:
                md5_extracted = get_md5sum(extracted_file)
                basename = os.path.basename(extracted_file)
                if basename == "audit.txt":
                   continue
                if md5 == md5_extracted:
                   continue 
                #extracted_file_path = output_dir+"/"+extracted_file
                if extracted_file not in extracted_files_lst:
                   extracted_files_lst.append(extracted_file)
    except:
       return extracted_files_lst
    return extracted_files_lst         


def get_random():
    from random import choice
    from string import ascii_uppercase

    return (''.join(choice(ascii_uppercase) for i in range(12)))


def walktree(file_dir):
    file_lst = []
    for root, dirs, files in os.walk(file_dir):
        for file_name in files:
           file_path = root+"/"+file_name 
           file_lst.append(file_path)
    return file_lst


def extract_zip(my_dir, my_zip): 
   file_lst = []
   magic_type = magic.from_file(my_zip)
   if not re.search("Zip", magic_type):
      return file_lst
   if os.path.exists(my_dir):
       shutil.rmtree(my_dir)
   os.mkdir(my_dir)
   try:
      with zipfile.ZipFile(my_zip) as zip_file:
       for member in zip_file.namelist():
        filename = os.path.basename(member)
        # skip directories
        if not filename:
            continue
        file_path = my_dir+"/"+filename
        file_lst.append(file_path)
        # copy file (taken from zipfile's extract)
        source = zip_file.open(member)
        target = file(os.path.join(my_dir, filename), "wb")
        with source, target:
            shutil.copyfileobj(source, target)
   except:
        return file_lst
   return file_lst


def get_iso_date_in_microseconds():
    i = datetime.now()
    date = ("%04d-%02d-%02dT%02d:%02d:%02d.%d" % (i.year, i.month, i.day, i.hour, i.minute, i.second, i.microsecond) )
    return  date

def get_size(filename):
    st = os.stat(filename)
    return st.st_size

def clean_up_dir(mime_attachment_directory):
    if os.path.exists(mime_attachment_directory):
       shutil.rmtree(mime_attachment_directory)
    os.mkdir(mime_attachment_directory)


def get_short_domain(domain):
    short_domain = ""
    if re.search("https", domain):
       domain = domain.strip("https://")
    elif re.search("http", domain):
       domain = domain.strip("http://")
    elif re.search("ftp", domain):
       domain = domain.strip("ftp//")
    short_domain_lst = domain.split(".")
    short_domain_lst = short_domain_lst[:-2]
    for i in short_domain_lst:
       short_domain+="."+i
    short_domain = short_domain.lstrip(".")
    return short_domain


def get_short_domain1(url):
    """Return top two domain levels from URI"""
    format_lst = ["exe", "php", "html", "gif"]
    re_3986_enhanced = re.compile(r"""
        # Parse and capture RFC-3986 Generic URI components.
        ^                                    # anchor to beginning of string
        (?:  (?P<scheme>    [^:/?#\s]+): )?  # capture optional scheme
        (?://(?P<authority>  [^/?#\s]*)  )?  # capture optional authority
             (?P<path>        [^?#\s]*)      # capture required path
        (?:\?(?P<query>        [^#\s]*)  )?  # capture optional query
        (?:\#(?P<fragment>      [^\s]*)  )?  # capture optional fragment
        $                                    # anchor to end of string
        """, re.MULTILINE | re.VERBOSE)
    result = ""
    m_uri = re_3986_enhanced.match(url)
    if m_uri and m_uri.group("authority"):
        auth = m_uri.group("authority")
        paths = m_uri.group("path")
        path = paths.split("/")
        path = filter(lambda s: len(s) > 0, path)
        path_length = len(path)
        count = 1
        url_path = ""
        if path_length> 1:
           object_path1 = path[1].split(".")
           flag = 0
           for i in object_path1:
              if i in format_lst:
                 flag = 1
           if flag ==1:
              url_path = path[0]
           else:
              url_path = path[0]+"/"+path[1]

        scheme = m_uri.group("scheme")
        result = auth+"/"+url_path
    return result

if __name__ == "__main__":
   print "Hello World!"
