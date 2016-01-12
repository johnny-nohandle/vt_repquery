vt_repquery
===========

Description
-----------
VT_REPQUERY is a simple utility written in python that uses the VirusTotal API 2.0 to query for reports regarding a specific file hash or url. The result are parsed and will only display positive or unrated results. The utility reads a configuration file (vt_repquery.cfg) which should contain the users VT API key. The VT API key will be tied to each query; the limit imposed by VT is 4 queries per minute.

Usage
-----
**Running vt_repquery**

 ./vt_repquery.py [OPTION] [ARG]

**Supported Switches:**

* -h = Usage
* -f path\to\file = to hash a file and query the hash in virustotal
* -s md5_hash = to query a hash in virustotal
* -u full_url = to query a url in virustotal

Item of note
------------
setup.py can be used with py2exe to create an executable version of vt_repquery.py for those systems that do not have python.