#!/usr/local/bin/python

import sys, time
import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *

analyzer = import_from("virustotal_data_mining_analyzer")
database = import_from("functions_database")

for search_tbl in search_lst:
      count = 0
      next_page = None
      while count < 4:
            count +=1      
            next_page, hashes = analyzer.get_matching_files(search_tbl, page=next_page)
            if hashes == None:
               print "You do not have enough privilledge to run the API, please contact VirusTotal for a valid Key."
               os._exit(0)
            for md5 in hashes:
                report = analyzer.get_report_all_info(md5)
                if len(report) == 0:
                   continue
                positives = report.get("positives")
                md5 = report.get("md5")
                if positives >= 6:
                   sha256 = report.get("sha256")
                   for key in report :
                      if key == "scans":
                         scan_report = report.get(key)
                         av_score = analyzer.get_av_engine_score_vti_search_report(scan_report)
                         mal_tbl  = analyzer.get_malware_tbl(md5)
                         mal_sev = mal_tbl.get("severity")
                         score = av_score+mal_sev
                         if (score >=8  and score <10):
                             if mangodb:
                                database.insert_data(md5, mal_tbl, "high_scored", sha256)
                             else:
                                analyzer.collect_data_in_csv_format(md5, mid_scored_hashes, mal_tbl)
                         elif (av_score >=10):
                             if mangodb:
                                database.insert_data(md5, mal_tbl, "mid_scored", sha256)
                             else:
                                analyzer.collect_data_in_csv_format(md5, high_scored_hashes, mal_tbl)
  
                else:
                    print "Positives AV engines on hash "+md5+" is: "+str(positives)


