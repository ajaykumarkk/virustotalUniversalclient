#
# Name...............Virus Total API CLient
# Author.............Ajay Kumar K K
#               
#
import requests
import time
import csv
import sys
import hashlib


class GetOutOfLoop(Exception):
	pass

def chunkIt(seq, num):
	avg = len(seq) / float(num)
	out = []
	last = 0.0
	while last < len(seq):
		if seq[int(last):int(last + avg)] != []:
			out.append(seq[int(last):int(last + avg)])
		last += avg
	return out

def md5Checksum(filePath):
	with open(filePath, 'rb') as fh:
		m = hashlib.md5()
		while True:
			data = fh.read(8192)
			if not data:
				break
			m.update(data)
		return m.hexdigest()


def getdata(data, apikey, type):
	params = {'apikey': apikey, 'resource': data}
	headers = {"Accept-Encoding": "gzip, deflate",
			   "User-Agent": "gzip,  My Python requests library example client or username"}
	response_dict = {}
	try:
		if type == 'hash':
			r = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
		elif type == 'file':
			url = 'https://www.virustotal.com/vtapi/v2/file/scan'
			params = {'apikey': apikey}
			files = {'file': ('myfile.exe', open(data, 'rb'))}
			r = requests.post(url, files=files, params=params)
		if r.status_code == 403:
			return "Forbidden. You don't have enough privileges to make the request"
		elif r.status_code == 204:
			return "Request rate limit exceeded"
		elif r.status_code == 400:
			return "Bad Request"
		elif r.status_code == 200:
			response_dict = r.json()
			return response_dict
	except Exception as e:
		print(e)
		return "API Request Error"
	return response_dict


def checkVThash(lines, apikeys, checknotvt):
	if len(apikeys) <= 14:
		waitime = (60 - len(apikeys) * 4)
	else:
		waitime = 3
	csv_handle = open('output_hashes.csv', 'w')
	invt = []
	flag = 0
	el_flag = True
	print("Total no.of hashes loaded is :" + str(len(lines)))
	hashes = iter(lines)
	unprocessed = []
	notinvt = []
	count = 0
	try:
		while el_flag:
			for api_key in apikeys:
				for i in range(0, 4):
					response_dict = {}
					hash = ""
					count = count + 1
					try:  # getting hashes from iterator
						hash = next(hashes)
					except:
						print("End of list")
						el_flag = False
						raise GetOutOfLoop
					response_dict = getdata(hash, api_key, 'hash')
					sample_info = {}
					if isinstance(response_dict, str):
						# print("request error for hash :"+hash)
						# print("-->"+response_dict+" for Hash "+hash)
						if response_dict == "Request rate limit exceeded":
							# print("Changing api key..")
							unprocessed.append(hash)
							break
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 0:
						print("Not in VT for hash :"+str(hash))
						notinvt.append(hash)
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == -2:
						print("In queue for scanning")
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 1:
						if checknotvt == 0:
							# Hashes
							sample_info["md5"] = response_dict.get("md5")
							# AV matches
							sample_info["positives"] = response_dict.get("positives")
							sample_info["total"] = response_dict.get("total")
							csv_handle.write(sample_info["md5"] + "," + str(sample_info["positives"]) + "," + str(
								sample_info["total"]))
							print(sample_info["md5"] + "," + str(sample_info["positives"]) + "," + str(
								sample_info["total"]), end='\n')
							csv_handle.write('\n')
						else:
							invt.append(response_dict.get("md5"))
					else:
						print("Unknown Error for hash " + hash)
						unprocessed.append(hash)
				# print("Api Key has ran 4 times.. Changing APi Key..\n")
				time.sleep(1)
			print("WaitTime is " + str(waitime) + " Seconds")
			for i in range(1, waitime):
				print(i, end="\r")
				time.sleep(1)
	except GetOutOfLoop:
		csv_handle.close()
	print("unprocessed hashes " + str(unprocessed))
	print("Hashes in Not in VT" + str(notinvt))
	with open('unprocessed_hashes.txt', 'w') as f:
		for item in unprocessed:
			f.write("%s\n" % item)
	if checknotvt == 1:
		return notinvt, invt


def VTfileupload(files, apikeys):
	lines=files.keys()
	if len(apikeys) <= 14:
		waitime = (60 - len(apikeys) * 4)
	else:
		waitime = 3
	csv_handle = open('file_upload.csv', 'a')
	flag = 0
	el_flag = True
	print("Total no.of paths loaded is :" + str(len(lines)))
	paths = iter(lines)
	unprocessed = []
	count = 0
	try:
		while el_flag:
			for api_key in apikeys:
				for i in range(0, 4):
					response_dict = {}
					path = ""
					count = count + 1
					try:  # getting hashes from iterator
						path = next(paths)
					except:
						print("End of list")
						el_flag = False
						raise GetOutOfLoop
					response_dict = getdata(files[path], api_key, 'file')
					sample_info = {}
					if isinstance(response_dict, str):
						#print("request error for path :" + path)
						print("-->" + response_dict + " for path " + files[path])
						if response_dict == "Request rate limit exceeded":
							print("Changing api key..")
							unprocessed.append(path)
							break
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 0:
						print("Not in VT for path :" + str(path))
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == -2:
						print("In queue for scanning")
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 1:
						sample_info["scan_id"] = response_dict.get("scan_id")
						sample_info["verbose_msg"] = response_dict.get("verbose_msg")
						csv_handle.write(
							path + "," + str(sample_info["verbose_msg"]) + "," + str(sample_info["scan_id"]))
						print(sample_info)
					else:
						print("Unknown Error for path " + path)
						unprocessed.append(path)
				# print("Api Key has ran 4 times.. Changing APi Key..\n")
				time.sleep(1)
			print("WaitTime is " + str(waitime) + " Seconds")
			for i in range(1, waitime):
				print(i, end="\r")
				time.sleep(1)
	except GetOutOfLoop:
		csv_handle.close()
	print("unprocessed paths " + str(unprocessed))
	with open('file_unprocessed.txt', 'w') as f:
		for item in unprocessed:
			f.write("%s\n" % item)
