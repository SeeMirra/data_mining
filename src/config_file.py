#!/usr/local/bin/python

#vt_key = <ENTER YOUR Virus Total Key here!>

#Directory to place the obtained medium scored hashes. The file needs to be in csv format
mid_scored_hashes = "/tmp/mid_scored_hashes.csv"

#Directory to place the obtained high scored hashes. The file needs to be in csv format
high_scored_hashes = "/tmp/high_scored_hashes.csv"

#directory to place the obtained urls. The file needs to be in csv format.
url_data = "/tmp/url_data.csv"

#place the directory of bin folder here
#bin_dir = <"/data_mining-master/bin">

#specify the criteria that you would like to use in VTI search
search_lst = [{"type": "executable", "positives": "7"+"+", "size":"90kb+"}, 
              {"type": "document", "positives": "7"+"+","size":"90kb+"},
              {"behaviour":"explorer.exe", "positives": "7"+"+"},
              {"tag": "trusted", "positives": "7+"},
              {"sources":"2000+" ,"symantec":"infected"},
              {"tag": "NSRL", "positives": "5+"},
              {"tag":"software-collection", "symantec":"infected", "positives": "5+"},
              {"tag": "worm", "positives": "5+"},
              {"tag": "trojan", "positives": "5+"},
              {"tag": "shellcode", "positives": "5+"},
              {"tag": "exploit-kit", "positives": "5+"}
              ]

