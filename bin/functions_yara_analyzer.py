#!/usr/bin/python

__description__ = "Apply Yara rules"
__author__="Gita Ziabari"
__version__="0.0.2"
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


import os, sys
import yara
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


def run_yara_rules(file_path, yara_rules_dir):
    matched_tbl = {}
    rule_dict = build_file_path_tbl(yara_rules_dir)
    try:
       rules = yara.compile(filepaths=rule_dict)
       matches = rules.match(file_path)
       if len(matches) == 0:
          return matched_tbl
       matched_tbl[file_path] = matches
    except:
      return matched_tbl
    return matched_tbl


def build_file_path_tbl(yara_rules_dir):
    rule_dict = {}
    try:
      for rule in os.listdir(yara_rules_dir):
        rand_key = get_random()
        rule_dict[rand_key] = yara_rules_dir+rule
    except:
      return rule_dict
    return rule_dict


if __name__ == "__main__":
   print "Hello World!"
