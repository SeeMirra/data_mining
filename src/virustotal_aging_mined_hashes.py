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

md5_lst = database.get_md5_lst()

for hash_name in md5_lst:
            report = analyzer.get_report_all_info(hash_name)
            if len(report) == 0:
                 continue
            positives = report.get("positives")
            md5 = report.get("md5")
            if positives < 4:
                 scan_report = report.get("scans")
                 av_score = analyzer.get_av_engine_score(scan_report)
                 mal_tbl  = analyzer.get_malware_tbl(md5)
                 mal_sev = mal_tbl.get("severity")
                 score = av_score+mal_sev

                 if (score < 6):
                     database.remove_data(md5)



