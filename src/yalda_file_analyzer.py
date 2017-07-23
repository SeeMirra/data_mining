#!/usr/local/bin/python
# -*- coding: utf-8

__description__ = "Main script to be executed for decoding scanning files"
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

import sys, time, re

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


mime_analyzer = import_from("functions_email_parser")
database = import_from("functions_database")
parser = import_from("functions_file_nalyzer")
yara_analyzer = import_from("functions_yara_analyzer")
vt_analyzer = import_from("functions_vt_analyzer")

md5s_seen = database.get_strings_collection()

#strings seen in malicious files
database_strings_collection = database.get_strings_collection()

if clean_up_mime_directory:
   clean_up_dir(mime_attachment_directory)

md5_lst = []
seen = []

for root, dirs, files in os.walk(data_dir):
    for file_name in files:
           file_path = root+"/"+file_name
           file_path_md5 = get_md5sum(file_path)
           extracted_file_lst = []
           extracted_file_lst = parser.get_extracted_files(file_path, seen)
           for extracted_file in extracted_file_lst:
               if extracted_file in seen:
                  continue
               seen.append(extracted_file)
               file_info = {}
               md5 = get_md5sum(file_path)
               if md5 in md5s_seen:
                  print "--- File "+file_path+" is already seen in database and information could be queried from database"
               file_info = parser.decode_file(extracted_file)
               if yara_check:
                  match_tbl = yara_analyzer.run_yara_rules(file_path, yara_rules_dir)
                  if match_tbl != {}:
                     yara_results = (match_tbl.values())[0]
                     file_info["Yara_Attr"]=str(yara_results)
                  else:
                     file_info["Yara_Attr"]=[]
               md5_lst.append(md5)
               embedded_files = []
               embedded_files = get_embedded_objects_run_foremost(extracted_file, mime_attachment_directory) 
               file_info.setdefault("embedded_files", embedded_files)
               strings_score, common_md5_tbl = parser.score_file_strings_base(file_path, database_strings_collection)
               high_scored_md5_lst = parser.get_top_ten_common_md5_lst(common_md5_tbl, md5)
               severity, flag = parser.set_flag_sev(embedded_files, match_tbl, file_info, strings_score, high_scored_md5_lst) 
               file_info["Flag"] = flag
               file_info["Severity"] = severity
               file_info["Similar_MD5"] = high_scored_md5_lst
               if vt_check == 1:
                  positives, paramalink = vt_analyzer.get_report_all_info(md5) 
                  if positives == None:
                     vt_exist = False
                  else:
                     vt_exist = True
                  
                  vt_dict = {"positives": positives,
                             "paramalink": paramalink,
                             "vt_exist": vt_exist}
                  file_info["VT_Info"] = vt_dict

               database.insert_file_detailed_info_in_database(file_info)
               #print file_info  
               if flag == "malicious" or severity>=1:
                  strings_collection = parser.build_up_strings_collection(file_path, database_strings_collection)
                  if strings_collection!=None:
                      #insert it in database only if it doesn't already exist 
                      database.insert_strings_collection(strings_collection)
                  #similar_hashes = get_similar_hashes(file_path)
               for embed_file in embedded_files:
                      if embed_file in seen:
                         continue
                      seen.append(embed_file)
                      embed_file_info = {}
                      basename = os.path.basename(embed_file)
                      if basename == "audit.txt":
                         continue
                      efile = embed_file
                      embed_md5 = get_md5sum(efile)
                      embed_file_info =  parser.decode_file(efile) 
                      embed_file_info.setdefault("Parent", file_path)
                      embed_file_info.setdefault("Parent_md5", file_path_md5)
                      if yara_check:
                         embed_match_tbl = yara_analyzer.run_yara_rules(embed_file, yara_rules_dir)
                         if embed_match_tbl != {}:
                            embed_yara_results = (embed_match_tbl.values())[0]
                            embed_file_info["Yara_Attr"]=str(embed_yara_results)
                         else:
                            embed_file_info["Yara_Attr"]=[]

                      strings_score, common_md5_tbl = parser.score_file_strings_base(file_path, database_strings_collection)
                      high_scored_md5_lst = parser.get_top_ten_common_md5_lst(common_md5_tbl, md5)
                      severity, flag = parser.set_flag_sev(embedded_files, match_tbl, embed_file_info, strings_score, high_scored_md5_lst)
                      embed_file_info["Flag"] = flag
                      embed_file_info["Severity"] = severity
                      embed_file_info["Similar_MD5"] = high_scored_md5_lst
                      if vt_check == 1:
                         positives, paramalink = vt_analyzer.get_report_all_info(md5)
                         if positives == None:
                            vt_exist = False
                         else:
                            vt_exist = True
                  
                         vt_dict = {"positives": positives,
                                    "paramalink": paramalink,
                                    "vt_exist": vt_exist}
                         embed_file_info["VT_Info"] = vt_dict
 
                      database.insert_file_detailed_info_in_database(embed_file_info)
                      #print embed_file_info

                      if flag == "malicious" or severity>=2:
                         embed_strings_collection = parser.build_up_strings_collection(embed_file, database_strings_collection)
                         if embed_strings_collection != None:
                            database.insert_strings_collection(embed_strings_collection)
           time.sleep(3)


