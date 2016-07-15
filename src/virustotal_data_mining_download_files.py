#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


analyzer = import_from("virustotal_data_mining_analyzer")

for hash_file_path in download_files_lst:
   boolian =  boolian_file_exist(hash_file_path)
   if not boolian:
        print hash_file_path+" doesn't exist. Please schedule running this script after virustotal_data_mining_file.py"
   else:
       md5_lst = analyzer.get_md5_from_high_scored_data(hash_file_path)
       if md5_lst == False:
          print "no data is available, schedule to run the script later"
          sys.exit()

       for md5 in md5_lst:
           analyzer.download_file_vt(md5, data_dir)


