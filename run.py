from src.vt_client import *
import os
import shutil

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
		else:
			shutil.move(i, "file_upload\\notuploaded")
print(files)

to_scan , scanned = checkVThash(files.values(),api_keys_list[0],1)
toscan_f={}
if len(to_scan) > 0:
	print("Uploading......")
	for p,h in files.items():
		if h in to_scan:
			toscan_f[h] = p
	VTfileupload(toscan_f,api_keys_list[1])

if len(scanned) > 0:
	print("Moving Scanned files......")
	for p,h in files.items():
		if h in scanned:
			try:
				shutil.move(p,"file_upload\\notuploaded")
			except Exception as e:
				print(e)



f=open('fileuploadhash.txt','a+')
for i in toscan_f.keys():
	f.write(i+"\n")
f.close()

