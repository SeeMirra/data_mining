#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


analyzer = import_from("virustotal_data_mining_analyzer")
database = import_from("functions_database")


if not mangodb:
   print "This script is only available for hashes inserted in mangoDB. Please enable it and try again!"
   sys.exit()

url_lst = database.get_url_lst()

for url in url_lst:
            report = analyzer.get_url_report(url)
            if len(report) == 0:
                 continue
            positives = report.get("positives")
            
            if positives < 5:
               database.remove_data(url)



