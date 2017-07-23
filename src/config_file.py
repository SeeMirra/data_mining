#!/usr/bin/python

__description__ = "Config File"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="07/22/2017"

"""
    This file is part of Yalda.

    Yalda is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    Yalda is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Yalda.  If not, see <http://www.gnu.org/licenses/>.
"""


'''place the directory of bin folder here'''
bin_dir = "<bin dir >"

'''indicate directory of files to be parsed---place all of your files in this directory for analysis'''
data_dir = "<Files directory >"


'''Yara Analysis'''
yara_check = 1   #enabled = 1; disabled = 0
'''Place yara rules in this directory'''
yara_rules_dir = "<yara rules directory>"

'''VT Analysis'''
'''Enable vt_key if you would like to get extra information frm Virus Total '''
vt_check = 0    #enabled = 1; disabled = 0
'''add your virus total key'''
vt_key = 'vt key'

#indicate directory to download mail attachments
mime_attachment_directory = "<directory for placing extracted files in it>"

#clean up mail directory prior executing the script
clean_up_mime_directory = 1   #anabled = 1, disabled = 0 


#specify mongodb credentials here
localhost = "IP address of mongodb"
port = 22     #port number for connecting to mongodb
db_name = 'amfm_db'
collection_name = 'yalda_collection'



