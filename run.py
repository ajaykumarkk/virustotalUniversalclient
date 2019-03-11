from src.vt_client import *
import os

with open('src//apikeys.txt', 'r') as f:
	apikeys = [line.rstrip('\n') for line in open('src//apikeys.txt')]

files_path = [os.path.abspath("file_upload\\"+x) for x in os.listdir("file_upload")]
files={}
for i in files_path:
	filename,ext = os.path.splitext(i)
	if ext == ".exe":
		if os.path.getsize(i) < 32000000:
			files[i]=md5Checksum(i)
print(files)
