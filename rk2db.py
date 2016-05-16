#!/usr/bin/env python3
import os, hashlib, sqlite3
con = sqlite3.connect("db.sqlite3")
cur = con.cursor()
for dirpath, dirnames, filenames in os.walk("RootkitScripts"):
    for filename in (f for f in filenames):
        fullfilename = os.path.join(dirpath, filename)
        with open(fullfilename, "rb") as content_file:
            content = content_file.read()
            hasher = hashlib.md5()
            hasher.update(content)
            digest = hasher.hexdigest()
            present = list(cur.execute("SELECT * FROM malware WHERE md5 = '%s'" % digest))
            info = (digest, fullfilename)
            if present:
                print("Digest %s for %s already present" % info)
                continue
            print("Inserting digest %s for %s..." % info)
            cur.execute("INSERT INTO malware (md5, name) VALUES ('%s', '%s')" % info)
            con.commit()
