#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Skeleton Key Scanner
#
# Detection is based on three detection methods:
#
# 1. File Name IOC 
#
# 2. Yara Ruleset
#
# 3. Hash Check
#    Compares known malicious SHA1 hashes with scanned files
#
# If you like Skeleton Key Scanner you'll love THOR our full-featured APT Scanner
# 
# Florian Roth
# BSK Consulting GmbH
# January 2015
# v0.1
# 
# DISCLAIMER - USE AT YOUR OWN RISK.

import sys
import os
import argparse
import scandir
import traceback
import yara
import hashlib
import wmi
import re
from colorama import Fore, Back, Style
from colorama import init

EVIL_FILES = [ 'msuta64.dll' ]

EVIL_HASHES = [ 'ad61e8daeeba43e442514b177a1b41ad4b7c6727', '5083b17ccc50dd0557dfc544f84e2ab55d6acd92' ]
FALSE_POSITIVES = [ ]

def scanPath(path, rules):
	
	# Startup
	print "Scanning %s ...  " % path ,
	# Compromised marker
	compromised = False
	c = 0
	
	for root, directories, files in scandir.walk(path, onerror=walkError, followlinks=False):

			# Loop through files
			for filename in files:
				try:

					# Get the file and path
					filePath = os.path.join(root,filename)

					# Print files
					if args.printAll:
						print "[SCANNING] %s" % filePath

					# Counter
					c += 1

					printProgress(c)

					if args.dots:
						sys.stdout.write(".")

					file_size = os.stat(filePath).st_size
					# print file_size

					# File Name Checks -------------------------------------------------
					for file in EVIL_FILES:
						if file in filePath:
							print Fore.RED, "\bSKELETONKEY File Name MATCH: %s" % filePath, Fore.WHITE
							compromised = True

					# Hash Check -------------------------------------------------------
					if file_size > 200000:
						continue

					sha1hash = sha1(filePath)
					if sha1hash in EVIL_HASHES:
						print Fore.RED, "\bSKELETON KEY SHA16 Hash MATCH: %s FILE: %s" % ( sha1hash, filePath), Fore.WHITE
						compromised = True
					if sha1hash in FALSE_POSITIVES:
						compromised = False
						continue

					# Yara Check -------------------------------------------------------
					if 'rules' in locals():
						try:
							matches = rules.match(filePath)
							if matches:
								for match in matches:
									print Fore.RED, "\bSKELETONKEY Yara Rule MATCH: %s FILE: %s" % ( match, filePath), Fore.WHITE
									compromised = True
						except Exception, e:
							if args.debug:
								traceback.print_exc()

				except Exception, e:
					if args.debug:
						traceback.print_exc()
	
	# Return result
	return compromised


def scanProcesses(rules):
	# WMI Handler
	c = wmi.WMI()
	processes = c.Win32_Process()

	compromised = False
	
	for process in processes:

		try:	
			pid = process.ProcessId
			name = process.Name
			cmd = process.CommandLine
			if not cmd:
				cmd = "N/A"
			if not name:
				name = "N/A"
		except Exception, e:
			print Fore.MAGENTA, "Error getting all process information. Did you run the scanner 'As Administrator'?", Fore.WHITE
			continue

		if pid == 0 or pid == 4:
			print Fore.CYAN, "Skipping Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ), Fore.WHITE
			continue

		print Fore.GREEN, "Scanning Process - PID: %s NAME: %s CMD: %s" % ( pid, name, cmd ), Fore.WHITE

		# Psexec command check
		# Skeleton Key Malware Process
		if re.search(r'psexec .* [a-fA-F0-9]{32}', cmd, re.IGNORECASE):
			print Fore.RED, "\bProcess that looks liks SKELETON KEY psexec execution detected PID: %s NAME: %s CMD: %s" % ( pid, name, cmd), Fore.WHITE
			compromised = True
		
		# Yara rule match
		try:
			matches = rules.match(pid=pid)
			if matches:
				for match in matches:
					print Fore.RED, "\bSKELETONKEY Yara Rule MATCH: %s PID: %s NAME: %s CMD: %s" % ( match, pid, name, cmd), Fore.WHITE
					compromised = True			
		except Exception, e:
			print Fore.MAGENTA, "Error while process memory Yara check (maybe the process doesn't exist anymore or access denied). PID: %s NAME: %s" % ( pid, name), Fore.WHITE

	return compromised


def sha1(filePath):
	try:
		with open(filePath, 'rb') as file:
			file_data = file.read()
		return hashlib.sha1(file_data).hexdigest()
	except Exception, e:
		if args.debug:
			traceback.print_exc()
		return 0
	
					
def walkError(err):
	if args.debug:
		traceback.print_exc()


def printProgress(i):
	if (i%4) == 0:
		sys.stdout.write('\b/')
	elif (i%4) == 1:
		sys.stdout.write('\b-')
	elif (i%4) == 2:
		sys.stdout.write('\b\\')
	elif (i%4) == 3: 
		sys.stdout.write('\b|')
	sys.stdout.flush()

				
def printWelcome():
	print Back.CYAN, "                                                                    ", Back.BLACK
	print Fore.CYAN
	print "  SKELETON KEY SCANNER"
	print "  "
	print "  by Florian Roth - BSK Consulting GmbH"
	print "  Jan 2015"
	print "  Version 0.1"
	print "  "
	print "  DISCLAIMER - USE AT YOUR OWN RISK"
	print "  "
	print Back.CYAN, "                                                                    ", Back.BLACK
	print Fore.WHITE+''+Back.BLACK	


# MAIN ################################################################
if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='SKELETONKEY Scanner')
	parser.add_argument('-p', help='Path to scan', metavar='path', default='C:\\')
	parser.add_argument('--printAll', action='store_true', help='Print all files that are scanned', default=False)
	parser.add_argument('--noprocscan', action='store_true', help='Skip the process scan', default=False)
	parser.add_argument('--nofilescan', action='store_true', help='Skip the file scan', default=False)
	parser.add_argument('--dots', action='store_true', help='Print a dot for every scanned file to see the progress', default=False)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
	
	args = parser.parse_args()
	
	# Colorization
	init()
	
	# Print Welcome
	printWelcome()
	
	# Compiling yara rules
	if os.path.exists('skeletonkey_rules.yar'):
		rules = yara.compile('skeletonkey_rules.yar')
	else: 
		print "Place the yara rule file 'skeletonkey_rules.yar' in the program folder to enable Yara scanning."

	# Scan Processes
	if not args.noprocscan:
		result_proc = scanProcesses(rules)

	# Scan Path
	if not args.nofilescan:
		result_path = scanPath(args.p, rules)
	
	if result_path or result_proc:
		print Fore.RED+''+Back.BLACK
		print "\bRESULT: SKELETONKEY INDICATORS DETECTED!"
		print Fore.WHITE+''+Back.BLACK
	else:
		print Fore.GREEN+''+Back.BLACK
		print "\bRESULT: SYSTEM SEEMS TO BE CLEAN. :)"
		print Fore.WHITE+''+Back.BLACK

	raw_input("Press Enter to exit ...")