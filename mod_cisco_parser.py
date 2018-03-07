#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import requests
import webbrowser
import csv

from lxml import etree

cisco_title=""
type_vulnerability = ["MULTIPLE VULNERABILITIES",
"DENIAL OF SERVICE VULNERABILITY",
"BYPASS VULNERABILITY",
"FILE BYPASS VULNERABILITY",
"UNAUTHORIZED ACCESS VULNERABILITY",
"SQL INJECTION VULNERABILITY",
"CROSS-SITE SCRIPTING",
"COMMAND INJECTION VULNERABILITY",
"PRELOADING VULNERABILITY",
"INFORMATION DISCLOSURE VULNERABILITY",
"BYPASS VULNERABILITY",
"HTTP RESPONSE SPLITTING VULNERABILITY",
"DLL PRELOAD VULNERABILITY",
"INFORMATION DISCLOSURE VULNERABILITY",
"PRIVILEGE ESCALATION VULNERABILITY",
"COMMAND INJECTION VULNERABILITY",
"UNAUTHORIZED ACCESS VULNERABILITY",
"REMOTE CODE EXECUTION VULNERABILITY",
"STATIC KEY VULNERABILITY"]

def parser_cisco():

#	tree = etree.parse("CiscoSecurityAdvisory.xml")

	pageContent=requests.get('https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml') # text brut page content

	tree = etree.fromstring(pageContent.content) # return <Element rss at 0x7f088476ccf8>
	for tit in tree.xpath("/rss/channel/item/title"):
		print ("\n==============================================Title======================================================")
		cisco_title=tit.text.upper()
		print cisco_title
		print ("=========================================================================================================")

		print ("\n\t\t\t\t\t\t\t\t\t\t\tPublication date:")
                cisco_date_pub=tit.getnext().getnext().getnext().text
                print ('\t\t\t\t\t\t\t\t\t\t\t'+cisco_date_pub[:16])

		print ("\nDescription:")
		cisco_desc=tit.getnext().getnext().text
		#cisco_desc=" ".join(cisco_desc.split())
		cisco_desc=cisco_desc.lstrip(' ').rstrip(' ')
		d=re.search(r'(.*)<br />',cisco_desc)
		print (d.group().replace("\t", ""))

		risk="N/A"
		print ("\nRisque:")
		for r in type_vulnerability:
			if r in cisco_title:
				risk = r
		print risk

		print ("\nCVE:")
		cve_num=re.findall("CVE-\d+-\d+", cisco_desc)

		for cve in cve_num:
			c="https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cve
			print(c)

		print ("\nLink:")
                cisco_link=tit.getnext().text
                print (cisco_link)


def link_cisco():

		link = []

		pageContent=requests.get('https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml') # text brut page content

	        tree = etree.fromstring(pageContent.content) # return <Element rss at 0x7f088476ccf8>
        	for link_raw in tree.xpath("/rss/channel/item/guid"):
			link.append(link_raw.text)
		print link



# Main

#parser_cisco()
link_cisco()

