from src.vt_client import *
import os

with open('src//apikeys.txt', 'r') as f:
	apikeys = [line.rstrip('\n') for line in open('src//apikeys.txt')]
api_keys_list=chunkIt(apikeys,2)
files_path = [os.path.abspath("file_upload\\"+x) for x in os.listdir("file_upload")]
files={}
for i in files_path:
	filename,ext = os.path.splitext(i)
	if ext == ".exe":
		if os.path.getsize(i) < 32000000:
			files[i]=md5Checksum(i)
print(files)

to_scan , scanned = checkVThash(files.values(),api_keys_list[0],1)

if len(to_scan) > 0:
	print("Uploading......")
	toscan_f={}
	for p,h in files.items():
		if h in to_scan:
			toscan_f[h] = p
	VTfileupload(toscan_f,api_keys_list[1])

f=open('fileuploadhash.txt','a+')
for i in toscan_f.keys():
	f.write(i)
f.close()
