#!/usr/bin/python

__description__ = "Modules to call VT API"
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

import os, sys, re
import json
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

sys.path.append("../src/")
from config_file import *


def get_report_all_info(md5):
    import requests
    report_dict = {}
    params = {'resource': md5, 'apikey': vt_key, 'allinfo': 1}
    try:
       response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
       data = {"response_code":0}
       status = response.status_code
       if status !=200:
          return None, None
       response_json = response.json()
       positive = response_json["positives"]
       paramalink = response_json["permalink"]
    except: 
       return None, None
    return positive, paramalink

if __name__ == "__main__":
   pos, param = get_report_all_info("23b3aa7dcbb6f8525c112eb2a5e4dbb8")
   print pos, param
