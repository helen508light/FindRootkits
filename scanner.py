#!/usr/bin/env python3

import os, sys, re, time, hashlib, sqlite3
import os.path

regexes = [
	re.compile(rb"\Wrm \-rf /\W"),
	re.compile(rb"\xeb\x3e\x5b\x31\xc0\x50\x54\x5a\x83\xec\x64\x68\xff\xff\xff\xff\x68\xdf\xd0\xdf\xd9\x68\x8d\x99\xdf\x81\x68\x8d\x92\xdf\xd2\x54\x5e\xf7\x16\xf7\x56\x04\xf7\x56\x08\xf7\x56\x0c\x83\xc4\x74\x56\x8d\x73\x08\x56\x53\x54\x59\xb0\x0b\xcd\x80\x31\xc0\x40\xeb\xf9\xe8\xbd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00cp -p /bin/sh /tmp/.beyond; chmod 4755/tmp/.beyond"),
	re.compile(rb"mkfs\\.ext[1234]? /dev/sd[abcd]?"),
	re.compile(rb":\(\)\{\:\|:\&\};:"),
	re.compile(rb"\w+ > /dev/sda"),
	re.compile(rb".+? > /dev/sd[a-d]"),
	re.compile(rb"wget (http(s?)|ftp)://[\w\-/\._]+ -O- \| sh"),
	re.compile(rb"mv /home/\w/\* /dev/null")
	]
#128-bit base-16 strings (length = 32)
con = sqlite3.connect("db.sqlite3")
with con:
    cur = con.cursor()
    cur.execute("SELECT md5, name FROM malware")
    #md5s = ["0123456789abcdef0123456789abcdef",
    #        "fedcba9876543210fedcba9876543210"]
    md5s = {r[0]: r[1] for r in cur.fetchall()}

if os.geteuid() != 0:
    sys.exit("Please run this as root. If you don't trust the file, read the sources at %s" % os.path.abspath(__file__))

# Here was the line about the best Helen, but she prohibited to keep it
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
                        print("The file %d : %s is suspected to contain %s due to MD5 hash sum %s" % (fileno, fullfilename, md5s[digest], digest))
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
