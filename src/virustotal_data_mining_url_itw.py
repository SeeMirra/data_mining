#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *

analyzer = import_from("virustotal_data_mining_analyzer")


while True:
   url_lst = analyzer.get_url_from_feed(url_data)
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
                          if positives >= 5:
                             md5 = report.get("md5")
                             for key in report :
                                if key == "scans":
                                   scan_report = report.get(key)
                                   av_score = analyzer.get_av_engine_score_vti_search_report(scan_report)
                                   if (av_score >=5  and av_score <10):
                                      analyzer.collect_data_in_csv_format(md5, mid_scored_hashes)
                                   elif (av_score >=10):
                                      analyzer.collect_data_in_csv_format(md5, high_scored_hashes)

                          else:
                               print "Positives AV engines on hash "+md5+" is: "+str(positives)
   time.sleep(40)
