# Zagros-mine
Mining VirusTotal for operational data and applying quality control on the obtained results.

The tool is designed to get the most recent malicious hashes and URLs with no false positive from VirusTotal and apply a quality control on the obtained data. All the data being submitted to VirusTotal are being analyzed in real time by the tool and only the ones passing the algorithm will be added to the database. 


Following are the proposed domains for using the tool: 

-> Feed to Cuckoo sandbox. 

-> Tool to obtain categorized hashes based on malware types. 

-> Base tool in any research that requires the most recent malicious data with no false positive. 

-> Testing tool to analyze detection ratio of malicious data in a product. 

-> Performance testing tool.


Scripts:

The following scripts are included in the package, please check regularly for updates:

1.	virustotal_data_mining_file.py: It mines data based on live File feed API on minute basis. 

2.	virustotal_data_mining_vti_search.py: It mines data based on the applied vti search

3.	virustotal_data_mining_url.py: It mines data based on live URL feed API on minute basis.

4.  virustotal_data_mining_url_itw.py: It mines URLs and hashes based on live URL API and VTI search on minute basis.

5.  virustotal_data_mining_download_files.py: Downloads the most malicious hashes obtained by the first and second script. Run it with delay from the first two scripts.

6.  virustotal_data_mining_file_similar_to.py: Get the list of high scored mined hashes and find similar to hashes to the mined one. Run the script with delay from the rest to get the results.


How to run the tools

Open confilg_file.py and add the following data in it to be able to run the scripts:

1.	vt_key: You would need to obtain the key from Virus Total.

2.	mid_scored_hashes: Directory to place the obtained medium scored hashes. The file needs to be in csv format.

3.	high_scored_hashes: Directory to place the obtained high scored hashes. The file needs to be in csv format.

4.	url_dir: directory to place the obtained urls. The file needs to be in csv format.

5.	bin_dir: no need to change it.

6.	search_lst: specify the criteria that you would like to use in VTI search.

7.  download_files_lst: list of hashes that you would like to download files from mined hashes. 

8.  data_dir: enter the directory that you would like to download the files from VT based on the mined data.


Needed python modules

•	urllib2, urllib

•	json

•	requests

