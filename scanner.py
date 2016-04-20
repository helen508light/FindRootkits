#!/usr/bin/env python3

import os, sys, re, time, hashlib
import os.path

regexes = [re.compile(rb"\Wrm \-rf /\W")]
#128-bit base-16 strings (length = 32)
md5s = ["0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210"]

if os.geteuid() != 0:
    sys.exit("Please run this as root. If you don't trust the file, read the sources at %s" % os.path.abspath(__file__))

ans = input("Do you want to scan (y/N)?")
if ans != "y": sys.exit("Scanning aborted")
print("Scanning started")
hasher = hashlib.md5()
start = time.perf_counter()

fileno = scanned = 0
malicious = []
for dirpath, dirnames, filenames in os.walk("/"):
    for filename in (f for f in filenames):
        fileno += 1
        fullfilename = os.path.join(dirpath, filename)
        if fileno % 500 == 0:
            print("Checking file %d..." % fileno)
        try:
            mode = os.stat(fullfilename).st_mode
        except:
            print("Exception occurred while retrieving info for file %d : %s" % (fileno, fullfilename))
        if mode & 73: # 111 base-8
            try:
                with open(fullfilename, "rb") as content_file:
                    content = content_file.read()
                    hasher.update(content)
                    digest = hasher.hexdigest()
                    if digest in md5s:
                        print("The file %d : %s is suspected to contain malicious commands due to MD5 hash sum" % (fileno, fullfilename))
                        malicious.append(fullfilename)
                        continue
                    for r in regexes:
                        if r.search(content):
                            print("The file %d : %s is suspected to contain malicious commands" % (fileno, fullfilename))
                            malicious.append(fullfilename)
                            break
                    scanned += 1
            except Exception as e:     
                print("Exception occurred while working with file %d : %s (%s)" % (fileno, fullfilename, e))

finish = time.perf_counter()
print("Scanning finished. Total time: %s seconds" % (finish - start))
print("=" * 50)
print("FILES: total %d, scanned %d" % (fileno, scanned))
print("*" * 50)
print("LIST OF MALICIOUS FILES (%d)" % len(malicious))
for m in malicious:
    print(m)
