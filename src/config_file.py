#!/usr/local/bin/python

#vt_key = <ENTER YOUR Virus Total Key here!>

#Directory to place the obtained medium scored hashes. The file needs to be in csv format
mid_scored_hashes = "/tmp/mid_scored_hashes.csv"

#Directory to place the obtained high scored hashes. The file needs to be in csv format
high_scored_hashes = "/tmp/high_scored_hashes.csv"

#directory to place the obtained urls. The file needs to be in csv format.
url_data = "/tmp/url_data.csv"

#place the directory of bin folder here
bin_dir = "../bin"

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

#indicate directory of the obtained hashes that you would like to download files
download_files_lst = [high_scored_hashes, mid_scored_hashes]

#indicate directory to download files
data_dir = "/tmp/samples/"

#enable extraction by assign 1 to it.
extraction = 1

#indicate directory to save extracted data of each hash
extracted_data_dir = "/tmp/extract_dir"


# MangoDB Configuration
# Note: Please consider using either mangoDB or csv file storage
#enable mangodb, if you would like data get submitted to mangodb, set mangodb = 1 to enable
mangodb = 0

#Specify the mangoDB server
localhost = "IP Address goes here"

#Specify the port number to connect to mangoDB
port = 27018
