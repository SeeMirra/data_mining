#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *

analyzer = import_from("virustotal_data_mining_analyzer")
database = import_from("functions_database")


while True:
   if mangodb:
      url_lst = database.get_url_lst()
   else:
      url_lst = analyzer.get_url_from_feed(url_data)
      if url_lst == False:
         print "Please execute virustotal_data_mining_url.py to get list of URLs and try again!"
         sys.exit()
   length = len(url_lst)-10
   url_lst = url_lst[length:]

   for url in url_lst:
                 search_tbl = {"itw": url, "positives": "5+"}
                 page_counter = 0
                 next_page = None
                 while page_counter <= 4:
                       page_counter+=1
                       next_page, hashes = analyzer.get_matching_files(search_tbl, page=next_page)
                       for md5 in hashes:
                          report = analyzer.get_report_all_info(md5)
                          if len(report) == 0:
                              continue
                          positives = report.get("positives")
                          md5 = report.get("md5")
                          if positives >= 5:
                             sha256 = report.get("sha256")
                             for key in report :
                                if key == "scans":
                                   scan_report = report.get(key)
                                   av_score = analyzer.get_av_engine_score_vti_search_report(scan_report)

                                   mal_tbl  = analyzer.get_malware_tbl(md5)
                                   mal_sev = mal_tbl.get("severity")
                                   score = av_score+mal_sev
                                   if (score >=6  and score <11):
                                      if mangodb:
                                          database.insert_data(md5, mal_tbl, "mid_scored", sha256)
                                      else:
                                         analyzer.collect_data_in_csv_format(md5,mid_scored_hashes, mal_tbl)
                                   elif (score >=11):
                                      if mangodb:
                                          database.insert_data(md5, mal_tbl, "high_scored", sha256)
                                      else:
                                         analyzer.collect_data_in_csv_format(md5, high_scored_hashes, mal_tbl)

                          else:
                               print "Positives AV engines on hash "+md5+" is: "+str(positives)
   time.sleep(40)
