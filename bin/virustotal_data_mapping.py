#!/usr/bin/python

http_response_score = {"200" : 2,
                       "100" : 1,
                       "403" : 1,
                       "404" : 1
                      }


#categories could be found at https://www.forcepoint.com/master-database-url-categories
categories_score = {"blogs" : 1,
                   "uncategorized" : 0,
                   "malicious web sites": 4,              # sites containing code intentionally modify users
                   "suspicious content" : 1,              # sites with suspicious content
                   "business" : 0,
                   "known infection source" : 5,
                   "parked" : 0,
                   "phishing and other frauds" : 5,       # counterfeit legitimate sites
                   "business and economy": 0,             # Sites sponsored by or devoted to business firms
                   "travel" : 0,
                   "bot networks": 4,                     # Command and control centers
                   "parked domain": 0,                    # Sites that are expired, offered for sale, ..
                   "computersandsoftware" : 0,
                   "health" : 0,
                   "real estate" : 0,                     # Sites that provide information about renting, buying, selling
                   "information technology" : 0,          # Computers, software, the Internet and related business firms
                   "entertainment" : 0,
                   "compromised websites" : 5,            # Sites that are vulnerable and known to host an injected malicious
                   "dynamic content": 2,                  # URLs dynamically being generated
                   "not recommended site" : 3,
                   "potentially unwanted software" : 2,   # Sites altering operation of a user's hardware, software, ...
                   "web and email spam" : 2,
                   "application and software download" : 1,
                   "personal network storage and backup" : 1, #store personal files on web servers for backup or exchange
                   "hacking" : 5,
                   "elevated exposure" : 2,
                   "education" : 0,
                   "web hosting" : 0,
                   "marketing" : 0,
                   "radiomusic" : 0,
                   "internet radio and tv" : 0,
                   "videos" : 0,
                   "proxy avoidance" : 2,
                   "illegal or questionable" : 1,
                   "gambling" : 0,
                   "dynamic dns" : 3,                     # APT
}


engine_score_mapping = {
         'ALYac'               : 0,
         'AVG'                 : 0,
         'AVWARE'              : 0,
         'Ad-Aware'            : 0,
         'Aegislab'            : 0,
         'Agnitum'             : 0,
         'AhnLab-v3'           : 0,
         'Alibaba'             : 0,
         'Antiy_AVL'           : 0,
         'Arcabit'             : 0,
         'Avast'               : 0,
         'Avira'               : 0,
         'AegisLab'            : 0,
         'Baidu-international' : 0,
         'Bitdefender'         : 0,
         'Bkav'                : 0,
         'ByteHero'            : 0,
         'cat-quickhill'       : 0,
         'CMC'                 : 0,
         'ClamAV'              : 0,
         'Comodo'              : 0,
         'Cyren'               : 0,
         'DrWeb'               : 0,
         'Eset-Nod32'          : 0,
         'Emsisoft'            : 0,
         'F-Prot'              : 0,
         'F-Secure'            : 0,
         'Fortinet'            : 0,
         'Gdata'               : 0,
         'Ikarus'              : 0,
         'Jiangmin'            : 0,
         'K7AntiVirus'         : 0,
         'K7GW'                : 0,
         'Kaspersky'           : 0,
         'Kingsoft'            : 0,
         'Malwarebytes'        : 0,
         'McAfee'              : 0,
         'McAfee-GW-Edition'   : 0,
         'MicroWorld-eScna'    : 0,
         'microsoft'           : 0,
         'NANO-Antivirus'      : 0,
         'Panda'               : 0,
         'Qihoo-360'           : 0,
         'Rising'              : 0,
         'SUPERAntiSpyware'    : 0,
         'Sophos'              : 0,
         'Symantec'            : 0,
         'Tencent'             : 0,
         'TheHacker'           : 0,
         'TotalDefense'        : 0,
         'TrendMicro'          : 0,
         'TrendMicro-HouseCall': 0,
         'VBA32'               : 0,
         'VIPRE'               : 0,
         'ViROBOT'             : 0,
         'Zillya'              : 0,
         'Zoner'               : 0,
         'nProtect'            : 0,
}

malware_type_score = {
        'ADWARE':    1,
        'TROJWARE':  3,
        'WORM':      3,
        'VIRUS':     3,
        'ROOTKIT':   4,
        'SPYWARE':   2,
        'EXPLOIT':   3,
        "RANSOMWARE": 5,
        'RISKWARE':  2,
        'HOAX':      1,
        'POS':       4,
        'MALWARE':   2,
}

