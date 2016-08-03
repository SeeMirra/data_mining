#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


analyzer = import_from("virustotal_data_mining_analyzer")
database = import_from("functions_database")

while True:
   feed_file = analyzer.get_vt_file_feed()
   feed_report = analyzer.process_package(feed_file)
   for feed_entry in feed_report:
       md5 = feed_entry.get("md5")
       sha256 = feed_entry.get("sha256")
       positives = feed_entry.get("positives")
       if positives > 6:
          scan_report = feed_entry.get("scans")
          av_score = analyzer.get_av_engine_score(scan_report)
          mal_tbl  = analyzer.get_malware_tbl(md5)
          mal_sev = mal_tbl.get("severity")
          score = av_score+mal_sev
          if (score >=8  and score <12):
                if mangodb:
                   database.insert_data(md5, mal_tbl, "mid_scored", sha256) 
                else:
                   analyzer.collect_data_in_csv_format(md5, mid_scored_hashes, mal_tbl)
          elif (score >=12):
               if mangodb:
                   database.insert_data(md5, mal_tbl, "high_scored", sha256)
               else:
                   analyzer.collect_data_in_csv_format(md5, high_scored_hashes, mal_tbl)
          else:
               print "Total score of Antivirus Engines and malware score is "+str(score)+" and doesn't meet the minumim requirement!"

       else:
          print "Number of Antiviruses detecting hash "+md5+" malicious is only "+str(positives)+" and doesn't meet the minumim requirement!"
   remove_file(feed_file)
   time.sleep(40)
