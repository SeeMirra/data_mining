#!/usr/bin/python

__description__ = "Modules to scan given files in detail"
__author__="Gita Ziabari"
__version__="0.0.1"
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
import json
import magic
import shutil
import gzip
import tarfile
import zipfile
import struct
import pefile
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *
from functions_email_parser import *
from functions_decoder import * 
from functions_database import * 


def get_file_type(file_path):
    try:
       file_type = magic.from_file(file_path)
    except:
       return file_type
    return file_type


def process_gzip(package_path):
    extracted_files = []
    try:
       with gzip.open(package_path, mode='r:gz') as compressed:
          file_content = compressed.read()

          path_to_store = mime_attachment_directory + os.path.basename(package_path)[:-3]
       
          with open(path_to_store, 'w') as f:
               f.write(file_content)
          if path_to_store in extracted_files:
             return extracted_files
          extracted_files.append(path_to_store)
    except:
        return extracted_files
    return extracted_files


def get_extracted_files(file_path, seen, file_lst = []):
    compressed_lst = ["gzip compressed data", "POSIX tar archive", "zip", "gz", "tgz", "bz2", "tbz"]
    if file_path in file_lst:
       return file_lst
    if file_path in seen:
       return file_lst
    try:
       file_type = get_file_type(file_path)
       file_extension = (file_path.split(".")[-1]).strip(" ")
       if (file_extension in compressed_lst) or (file_type in compressed_lst):
           extracted_file_tbl = extract_compressed_files(file_path, file_type)
           for extracted_file in extracted_file_tbl:
               if extracted_file in file_lst:
                  continue
               extracted_file_extension =  (extracted_file.split(".")[-1]).strip(" ")
               if (extracted_file_extension not in compressed_lst):
                  file_lst.append(extracted_file)
               elif (extracted_file_extension in compressed_lst):
                  continue
               get_extracted_files(extracted_file, seen, file_lst)                
       elif re.search("ASCII English text", file_type):  
          extracted_files = extract_mime_attachments(file_path, file_type)
          for efile in extracted_files:
              efile_extension = efile.split(".")[-1].strip(" ") 
              if (efile_extension not in compressed_lst):
                 file_lst.append(efile)
              if efile in file_lst:
                 continue
              if (efile_extension in compressed_lst):
                 get_extracted_files(efile, seen, file_lst)
       else:
           if file_path in file_lst:
              return file_lst
           file_lst.append(file_path)
    except:
       return file_lst
    return file_lst


def extract_compressed_files(file_path, file_type):
    extracted_files=[]
    try:
     if file_path.endswith('.zip'):
       try:
          to_directory = mime_attachment_directory+ os.path.basename(file_path)[:-4]
          #to_directory = path[:-4]
          extracted_files = extract_zip(to_directory, file_path)
          return extracted_files
       except:
          return extracted_files
     elif file_path.endswith('.gz') and not file_path.endswith('.tar.gz'):
       try:
          extracted_files = process_gzip(file_path)
          return extracted_files
       except:
          return extracted_files
     elif file_path.endswith('.tar.gz'):
        to_directory = mime_attachment_directory + os.path.basename(file_path)[:-7]
        #to_directory = path[:-7]
        opener, mode = tarfile.open, 'r:gz'
     elif file_path.endswith('.tgz'):
        to_directory = mime_attachment_directory + os.path.basename(file_path)[:-4]
        #to_directory = path[:-4]
        opener, mode = tarfile.open, 'r:gz'
     elif path.endswith('.tar.bz2'):
        to_directory = mime_attachment_directory + os.path.basename(file_path)[:-8]
        #to_directory = path[:-8]
        opener, mode = tarfile.open, 'r:bz2'
     elif path.endswith('.tbz'):
        to_directory = mime_attachment_directory + os.path.basename(file_path)[:-4]
        #to_directory = path[:-4]
        opener, mode = tarfile.open, 'r:bz2'
     else: 
        raise ValueError, "Could not extract `%s` as no appropriate extractor is found" % path
        return extracted_files
    
     cwd = os.getcwd()
     if os.path.exists(to_directory):
       shutil.rmtree(to_directory)
     os.mkdir(to_directory)
     os.chdir(to_directory)
    
     try:
        file = opener(file_path, mode)
        try: file.extractall()
        finally: 
             file.close()
             extracted_files = os.listdir(to_directory)
             extracted_files = [os.path.join(to_directory+"/", f) for f in os.listdir(to_directory)]
     finally:
        os.chdir(cwd)
    except:
      return extracted_files
    return extracted_files


def extract_mime_attachments(file_path, file_type):
    '''Extract base64 mime attachements and return the list of attachments '''
    attachment_lst = []

    if re.search("ASCII English text", file_type):
       try:
          with open(file_path) as f:
             for line in f:
                json_load = json.loads(line)
                attachment_directory = file_path+"_attachments/"
                downloaded_files= get_mime_message(json_load, file_path, attachment_directory)
                attachment_lst+=downloaded_files
       except:
          return attachment_lst
    return attachment_lst

     
def decode_file(file_path):
    """Analyze file and extract malicious/suspicious domains out of it"""
    file_info = {}
    try:
     if os.path.exists(file_path):
    
      flag = "unknown"
      file_type_magic = magic.from_file(file_path)
      file_split = file_path.split(".")
      if len(file_split)<=1:
         file_type = file_type_magic.split(" ")[0].upper()
         if re.search("PE32", file_type):
            file_type = "EXE"
      else:
         file_type = (file_path.split(".")[-1]).upper()
         if re.search("PE32", file_type):
            file_type = "EXE"
      md5_hash = get_md5sum(file_path) 
      sha256_hash = get_sha256(file_path)
      sha1_hash = get_sha1(file_path)
      size = get_size(file_path)
      file_name = os.path.basename(file_path)
      domain_lst= extract_domain_lst(file_path, file_type_magic)
      if domain_lst == []:
         domain_lst = None
      pe_sections = get_pe_sections(file_path)
      file_info = {"File_Path": file_path,
                 'MD5': md5_hash,
                 'SHA256': sha256_hash,
                 'SHA1': sha1_hash,
                 'Size': size,
                 'Source': "yalda_mining_data",
                 'File_Type': file_type,
                 'Magic_literal': file_type_magic,
                 'Domain_lst': domain_lst,
                 'File_Type_Extension': file_type.lower(),
                 'File_Name' : file_name,
                 'PE_sections' : pe_sections
                }
    except:
       return file_info
    return file_info 


def get_flag_severity1(file_type, severity, file_path, flag):
    is_ole = is_embedded_ole(file_path)
    if is_ole:
       if flag == "unknown":
          flag = "suspicious"
       if severity<=2:
          severity+=1
    is_flash = is_embedded_flash(file_path)
    if is_flash:
       if flag == "unknown":
          flag = "suspicious"
       if severity<=2:
          severity+=1
    return flag, severity


def get_top_ten_common_md5_lst(md5_tbl, md5_file):
       md5_lst = []
       score_lst = md5_tbl.keys()
       if score_lst == []:
          return md5_lst
       score_lst.sort()
       
       short_lst = score_lst[-10:]
       for score in short_lst:
           md5 = md5_tbl.get(score)
           if md5 == md5_file:
              continue
           md5_lst.append(md5)
       return md5_lst


def score_file_strings_base(file_path, strings_dict):
    score = 0    #total number of times strings seen for all hashes
    count = 0    #number of times string seen for each md5
    md5_tbl = {}
    seen_strings= []
    file_strings = apply_strings(file_path) 
    if file_strings == []:
       return score, md5_tbl
    try:
     for md5 in strings_dict:
        total_per_md5 = 0    #number of time stringS seen in each md5
        string_lst = strings_dict.get(md5)
        seen_strings= []
        for eachstring in file_strings:
            if eachstring in seen_strings:
               #already calculated this one skip
               continue
            seen_strings.append(eachstring)
            if eachstring in string_lst:
                count = string_lst.count(eachstring)  #number of times the string is repeated for this md5
                
                score+=count #number of times the strings is repeated for all hashes detected as malicious
                total_per_md5+=count   #total number of common strings for this hash
        if total_per_md5 >=10:
           md5_tbl.setdefault(total_per_md5, md5)
    except:
       return score, md5_tbl
    return score, md5_tbl


def extract_domain_lst(file_path, file_type):
    domain_lst = []
    severity = 2
    try:
     if re.search("ASCII text", file_type):
       file_format = file_path.split(".")[-1]
       if file_format == "wsf":
          domain_lst, severity = parse_wsf_file(file_path)
     elif re.search("Rich Text Format data", file_type):  
          domain_lst, severity = parse_rtf_file(file_path)
     elif re.search("PDF document", file_type):
          domain_lst,severity = parse_pdf_file(file_path)
    except:
     return domain_lst
    return domain_lst
    

def parse_wsf_file1(zip_file):
    domain_lst=[]
    severity = 2
    if os.path.exists(zip_file):
     
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
      except:
         return domain_lst, severity
    return domain_lst, severity


def bool_json_check(file_path):
    try:
      json_object = json.loads(file_path)
    except ValueError, e:
      return False
    return True
          

def is_embedded_flash(file_path):
    boolean = False
    try:
     data = open(file_path, 'rb').read()
     if data[:3] not in ["CWS", "FWS"]:
        if "ShockwaveFlash" in data and ("CWS" in data or "FWS" in data):
                #Find embedded flash file
                offset = data.find("FWS")
                if offset == -1:
                   offset = data.find("CWS")
                   if offset == -1:
                      print("Not found")
                   else:
                      boolean = True
                else:
                   sz = struct.unpack_from('<I', data[offset-4:])[0]
                   flash_file = data[offset:offset+sz]
                   boolean = True
    except:
        return boolean
    return boolean

def is_embedded_ole(file_path):
    boolean = False
    try:
       data = open(file_path, 'rb').read()
       if "d0cf11e" in data:
          embedded_ole = re.findall(r'''d0cf11e[0-9a-f\r\n]+''',data)
          boolean = True
    except:
        return boolean
    return boolean


def apply_strings(file_path):
    """Appplies strings to the file and builds up list of strings converted to sha1"""
    sha1_tbl = []
    try:
       embedded_strings_unicode = command("strings -e l "+file_path)
       embedded_strings_all = command("strings -a "+file_path)
       strings_lst_unicode = embedded_strings_unicode.split("\n")
       strings_lst_unicode.remove("")
       strings_lst_all = embedded_strings_all.split("\n")
       strings_lst_all.remove("")
       strings_lst = strings_lst_unicode + strings_lst_all
       sha1_tbl = get_strings_sha1(strings_lst)
    except:
        return sha1_tbl
    return sha1_tbl


def get_strings_sha1(strings_lst):
    sha1_tbl = []
    try:
      for string in strings_lst:
        hex_str = hashlib.sha1(string).hexdigest()
        sha1_tbl.append(hex_str)
    except:
       return sha1_tbl
    return sha1_tbl


def build_up_strings_collection(file_path, database_strings_collection):
    #this is being done only if the file is malicious or has a high severity
    strings_collection = {}
    try:
       md5_lst_in_database = database_strings_collection.keys()
       md5 = get_md5sum(file_path)
       if md5 in md5_lst_in_database:
          return
       #string list is converted to sha1 hash 
       strings_lst = apply_strings(file_path)
       strings_collection = {"File_path":file_path,
                          "MD5": md5,
                          "Source": "yalda_strings_collection",
                          "Embedded_strings": strings_lst
                         }
    except:
       return strings_collection
    return strings_collection
 

def set_flag_sev(embedded_files, yara_match_tbl, file_info, strings_score, high_scored_md5_lst):
    """set the flag and severity based on returned results on yara rules and existance of embedded objects"""
    suspicious_filetype_lst = ['ADE', 'ADP', 'APP', 'ASA', 'ASP', 'BAS', 'BAT', 'CER', 'CHM', 'CMD', 'COM', 'CPL', 'CRT', 'CSH', 'DLL', 'EXE', 'FXP', 'HLP', 'HTA', 'HTM', 'HTML', 'HTR', 'INF', 'INS', 'ISP', 'ITS', 'JS', 'JSE', 'KSH', 'LNK', 'MAD', 'MAF', 'MAG', 'MAM', 'MAQ', 'MAR', 'MAS', 'MAT', 'MAU', 'MAV', 'MAW', 'MDA', 'MDB', 'MDE', 'MDT', 'MDW', 'MDZ', 'MHT', 'MHTM', 'MHTML', 'MSC', 'MSI', 'MSP', 'MST', 'OCX', 'OPS', 'PCD', 'PIF', 'PRF', 'PRG', 'REG', 'SCF', 'SCR', 'SCT', 'SHB', 'SHS', 'TMP', 'URL', 'VB', 'VBE', 'VBS', 'VBX', 'VSMACROS', 'VSS', 'VST', 'VSW', 'WS', 'WSC', 'WSF', 'WSH', 'XSL']
    flag = "unknown"
    severity = 1
    try:
       domain_lst = file_info.get('Domain_lst')
       file_type = file_info.get('File_Type')
       file_path = file_info.get('File_Path')
       if domain_lst!=None:
          flag = "malicious" 
          severity = 5
          return severity, flag
       if yara_match_tbl != {}:
          if flag == "unknown":
             flag = 'suspicious'
          if severity <=3:
             severity = 4  
       '''set flag and severity based on the embedded objects'''
       if len(embedded_files) > 0: 
          flag = 'suspicious'
          if severity <=3:
             severity+=1 
             if file_type in suspicious_filetype_lst:
                severity = 4 
       if strings_score>=500 and strings_score<=1000:
          if flag == "unknown":
             flag = "suspicious"
          if severity <=2:
             severity+=1  
       if strings_score>=1001:
          if flag == "unknown":
             flag = "suspicious"
          if severity <=3:
             severity+=1 
       if len(high_scored_md5_lst) >=9:
          if flag == "unknown":
             flag = "suspicious"
          if severity <=2:
             severity+=1
       is_ole = is_embedded_ole(file_path)
       if is_ole:
          if flag == "unknown":
             flag = "suspicious"
          if severity<=2:
             severity+=1
       is_flash = is_embedded_flash(file_path)
       if is_flash:
          if flag == "unknown":
             flag = "suspicious"
          if severity<=2:
             severity+=1
    except:
       return severity, flag
    return severity, flag


def get_pe_names(pe_tbl):
    pe_names = []
    try:
       for tbl in pe_tbl:
          for section in tbl:
             name = tbl.get(section)
             pe_names.append(name)
    except: 
       return pe_names
    return pe_names


def get_pe_sections(file_path):
    pe_sect = {}
    pe_tbl = []
    try:
       pe = pefile.PE(file_path)
       for sect in pe.sections:
          name = (sect.Name).strip("\x00")
          virtual_addr = sect.VirtualAddress 
          virtual_size = sect.Misc_VirtualSize
          rawdata_size = sect.SizeOfRawData
          md5_hash = sect.get_hash_md5()
          sha256_hash = sect.get_hash_sha256()
          sha1_hash_name =  hashlib.sha1(name).hexdigest() 
          entropy = round(sect.get_entropy(), 2)
          pe_sect = {"Name" : name,
                 "Virtual_address": virtual_addr,
                 "Virtual_size": virtual_size,
                 "Raw size":rawdata_size,
                 "MD5": md5_hash,
                 "SHA1_hash_name": sha1_hash_name,
                 "Entropy" : entropy,
                 "SHA256": sha256_hash}
          pe_tbl.append(pe_sect)
       return pe_tbl  
    except:
       return pe_tbl


if __name__ == "__main__":
   print "hi there"
