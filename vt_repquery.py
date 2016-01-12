import sys
import os
from ConfigParser import SafeConfigParser
import simplejson
import urllib
import urllib2
import hashlib
import argparse

app_version = "1.1.1"
cfg_fullpath = os.getcwd() + "\\" + "vt_repquery.cfg"

if os.path.isfile(cfg_fullpath):
    print('[*] Found config at {0}\n').format(cfg_fullpath)
else:
    bin_fullpath = sys.argv[0]
    cfg_fullpath = bin_fullpath.rsplit('\\', 1)[0] + '\\' + 'vt_repquery.cfg'
    print('[*] Found config at {0}\n').format(cfg_fullpath)

cfg_parser = SafeConfigParser()
if not cfg_parser.read(cfg_fullpath):
    sys.exit("\nERROR: config file not found.")
if not cfg_parser.has_section('vt_apikey'):
    sys.exit("\nERROR: config file section 'vt_apikey' not found.")
if not cfg_parser.has_option('vt_apikey', 'apikey'):
    sys.exit("\nERROR: config file section option 'apikey' not found.")

arg_parser = argparse.ArgumentParser()
group = arg_parser.add_mutually_exclusive_group()
group.add_argument("-f", "--file", action="store_true", help="full file location, generate an md5 hash and query VT with hash")
group.add_argument("-u", "--url", action="store_true", help="url, will query VT with url")
group.add_argument("-s", "--sum", action="store_true", help="hash, will query VT with hash")
arg_parser.add_argument("queryitem", help="the item (file, url, or hash) to be queried by VT")
args = arg_parser.parse_args()

def hash_funct(tgt_file):
    tgt_hash = hashlib.md5(open(tgt_file, 'rb').read()).hexdigest()
    print "\n[MD5 Hash]\t" + tgt_hash
    return(tgt_hash)

def url_report(tgt_url):
    url_2 = "https://www.virustotal.com/vtapi/v2/url/report"
    vtapi_parameters = {"resource": tgt_url, "apikey": ""}
    vtapi_parameters["apikey"] = cfg_parser.get("vt_apikey", "apikey")
    req_data = urllib.urlencode(vtapi_parameters)
    req_2 = urllib2.Request(url_2, req_data)
    try:
        req_response = urllib2.urlopen(req_2)
    except:
        print "\nERROR: %s" % (sys.exc_info()[1])
        sys.exit()
    jsondata_2 = req_response.read()
    datadict_2 = simplejson.loads(jsondata_2)

    scan_vendors = [
                'CLEAN MX','MalwarePatrol','ZDB Zeus','Netcraft'
                ,'K7AntiVirus','Quttera','AegisLab WebGuard','MalwareDomainList'
                ,'ZeusTracker','zvelo','Google Safebrowsing','Kaspersky'
                ,'BitDefender','Dr.Web','ADMINUSLabs','AlienVault'
                ,'C-SIRT','CyberCrime','Websense ThreatSeeker','VX Vault'
                ,'Webutation','G-Data','Malwarebytes hpHosts','Opera','WOT'
                ,'Emsisoft','Malc0de Database','SpyEyeTracker','malwares.com URL checker'
                ,'Phishtank','Malwared','Avira','StopBadware'
                ,'Antiy-AVL','SCUMWARE.org','Comodo Site Inspector','Malekal'
                ,'ESET','Sophos','Yandex Safebrowsing','SecureBrain'
                ,'Malware Domain Blocklist','ZCloudsec','PalevoTracker','AutoShun'
                ,'ThreatHive','ParetoLogic','URLQuery','Sucuri SiteCheck'
                ,'Wepawet','Fortinet'
                 ]
    
    if datadict_2.get("positives") == 0:
        print "\n[Total Positives]\t 0",
    elif str(datadict_2.get("response_code")) == "0":
        print "\n" + str(datadict_2.get("verbose_msg"))
    else:
        print "\n[Ratio]\t " + str(datadict_2.get("positives")) + "/" + str(datadict_2.get("total"))
        for vendor in scan_vendors:
            if str(datadict_2.get("scans", {}).get(vendor,{}).get("result", {})) != "None" and str(datadict_2.get("scans", {}).get(vendor,{}).get("result", {})) != 'clean site':
                print "\n[" + vendor + "]\t " + str(datadict_2.get("scans", {}).get(vendor,{}).get("result", {})),

def file_report(tgt_hash):
    url_1 = "https://www.virustotal.com/vtapi/v2/file/report"
    vtapi_parameters = {"resource": tgt_hash, "apikey": ""}
    vtapi_parameters["apikey"] = cfg_parser.get("vt_apikey", "apikey")
    req_data = urllib.urlencode(vtapi_parameters)
    req_1 = urllib2.Request(url_1, req_data)
    try:
        req_response = urllib2.urlopen(req_1)
    except:
        print "\nERROR: %s" % (sys.exc_info()[1])
        sys.exit()
    jsondata_1 = req_response.read()
    datadict_1 = simplejson.loads(jsondata_1)

    av_vendors = [
                'Bkav', 'MicroWorld-eScan', 'nProtect', 'CAT-QuickHeal',
                'McAfee', 'Malwarebytes', 'TheHacker', 'K7GW',
                'K7AntiVirus', 'NANO-Antivirus', 'F-Prot', 'Symantec',
                'Norman', 'TotalDefense', 'TrendMicro-HouseCall', 'Avast',
                'ClamAV', 'Kaspersky', 'BitDefender', 'Agnitum',
                'SUPERAntiSpyware', 'Ad-Aware', 'Emsisoft', 'Comodo',
                'F-Secure', 'DrWeb', 'VIPRE', 'AntiVir',
                'TrendMicro', 'McAfee-GW-Edition', 'Sophos', 'Jiangmin',
                'Antiy-AVL', 'Kingsoft', 'Microsoft', 'ViRobot',
                'AhnLab-V3', 'GData', 'Commtouch', 'ByteHero',
                'VBA32', 'Baidu-International', 'ESET-NOD32', 'Rising',
                'Ikarus', 'Fortinet', 'AVG', 'Panda', 'CMC',
                 ]

    if datadict_1.get("positives") == 0:
        print "\n[Total Positives]\t 0",
    else:
        print "\n[Ratio]\t " + str(datadict_1.get("positives")) + "/" + str(datadict_1.get("total"))
        for vendor in av_vendors:
            if str(datadict_1.get("scans", {}).get(vendor,{}).get("result", {})) != "None" and str(datadict_1.get("scans", {}).get(vendor,{}).get("result", {})) != '{}':
                print "\n[" + vendor + "]\t " + str(datadict_1.get("scans", {}).get(vendor,{}).get("result", {})),


tgt_object = args.queryitem

print "\nVersion %s" % (app_version)
if args.url:
    url_report(tgt_object)
elif args.file:
    tgt_hash = hash_funct(tgt_object)
    file_report(tgt_hash)
elif args.sum:
    file_report(tgt_object)
else:
    arg_parser.error("-f/--file or -u/--url must be used.")
    exit()