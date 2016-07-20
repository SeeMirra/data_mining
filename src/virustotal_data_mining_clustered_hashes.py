#!/usr/local/bin/python

import sys, time

from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


analyzer = import_from("virustotal_data_mining_analyzer")

date = get_yesterday()
cluster_report = analyzer.get_cluster_report(date)
for info in cluster_report:
      response_code = cluster_report.get("response_code")
      if response_code == 0:
         continue
      if info == "clusters":
         cluster_tbl = cluster_report.get("clusters")
         for cluster in cluster_tbl:
             val = cluster.get("id")
             json = analyzer.get_cluster_detail(val)
             for data in json:
                 if data == "hashes":
                    hash_tbl = json.get(data)
                    for element  in hash_tbl:
                          report = analyzer.get_report_all_info(element)
                          if len(report) == 0:
                              continue
                          positives = report.get("positives")
                          if positives >= 6:
                             md5 = report.get("md5")
                             for key in report :
                                if key == "scans":
                                   scan_report = report.get(key)
                                   av_score = analyzer.get_av_engine_score_vti_search_report(scan_report)
                                   
                                   mal_tbl  = analyzer.get_malware_tbl(md5)
                                   mal_sev = mal_tbl.get("severity")
                                   score = av_score+mal_sev
                                   
                                   if (score >=8  and score<12):
                                      analyzer.collect_data_in_csv_format(md5, mid_scored_hashes, mal_tbl)
                                   elif (score >=12):
                                      analyzer.collect_data_in_csv_format(md5, high_scored_hashes, mal_tbl)

                          else:
                               print "Positives AV engines on hash "+md5+" is: "+str(positives)


