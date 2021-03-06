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

def getKey(item):
	return item[0]

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
		elif type =='ip':
			url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
			params = {'apikey': apikey, 'ip': data}
			r = requests.get(url, params=params)
		elif type == 'url':
			url = 'https://www.virustotal.com/vtapi/v2/url/report'
			params = {'apikey': apikey, 'resource': data , 'scan':1}
			r = requests.get(url, params=params)
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
	csv_handle = open('output_hashes.csv', 'a+')
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
	csv_handle = open('file_upload.csv', 'a+')
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
							files[path] + "," + str(sample_info["verbose_msg"]) + "," + str(sample_info["scan_id"])+"\n")
						print(sample_info)

					else:
						print("Unknown Error for path " + path)
						unprocessed.append(files(path))
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


def getVTip(lines,apikeys):
	if len(apikeys) <= 14:
		waitime = (60 - len(apikeys) * 4)
	else:
		waitime = 3
	csv_handle = open('ip_output.csv', 'a+')
	flag = 0
	el_flag = True
	print("Total no.of ips loaded is :" + str(len(lines)))
	ips = iter(lines)
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
						ip = next(ips)
					except:
						print("End of list")
						el_flag = False
						raise GetOutOfLoop
					response_dict = getdata(ip, api_key, 'ip')
					sample_info = {}
					if isinstance(response_dict, str):
						# print("request error for path :" + path)
						print("-->" + response_dict + " for path " + ip)
						if response_dict == "Request rate limit exceeded":
							print("Changing api key..")
							unprocessed.append(ip)
							break
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 0:
						print("Not in VT for ip :" + str(ip))
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == -2:
						print("In queue for scanning")
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 1:
						try:
							if response_dict.get("detected_urls") is not None:
								sample_info["detected_urls"] = response_dict.get("detected_urls")
								scores=[]
								for i in sample_info["detected_urls"]:
									scores.append((i["positives"],i["total"]))
								sorted(scores, key=getKey)
								print(ip + "," + str(scores) + "\n")
							#print(scores)
						except Exception as e:
							print(e)
					else:
						print("Unknown Error for path " + ip)
						unprocessed.append(ip)
				# print("Api Key has ran 4 times.. Changing APi Key..\n")
				time.sleep(1)
			print("WaitTime is " + str(waitime) + " Seconds")
			for i in range(1, waitime):
				print(i, end="\r")
				time.sleep(1)
	except GetOutOfLoop:
		csv_handle.close()
	print("unprocessed ips " + str(unprocessed))
	with open('file_unprocessed.txt', 'w') as f:
		for item in unprocessed:
			f.write("%s\n" % item)

def getVTurl(lines,apikeys):
	if len(apikeys) <= 14:
		waitime = (60 - len(apikeys) * 4)
	else:
		waitime = 3
	csv_handle = open('url_output.csv', 'a+')
	flag = 0
	el_flag = True
	print("Total no.of url's loaded is :" + str(len(lines)))
	urls = iter(lines)
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
						url = next(urls)
					except:
						print("End of list")
						el_flag = False
						raise GetOutOfLoop
					response_dict = getdata(url, api_key, 'url')
					sample_info = {}
					if isinstance(response_dict, str):
						# print("request error for path :" + path)
						print("-->" + response_dict + " for path " + url)
						if response_dict == "Request rate limit exceeded":
							print("Changing api key..")
							unprocessed.append(url)
							break
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 0:
						print("Not in VT for ip :" + str(url))
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == -2:
						print("In queue for scanning")
					elif isinstance(response_dict, dict) and response_dict.get("response_code") == 1:
						try:
							pos=""
							tot=""
							if response_dict.get("positives") is not None:
								pos = response_dict.get("positives")
								tot = response_dict.get("total")
								csv_handle.write(url + ","+ str(pos) +","+ str(tot))
								csv_handle.write('\n')
							else:
								unprocessed.append(url)
						except Exception as e:
							print(e)
					else:
						print("Unknown Error for url " + url)
						unprocessed.append(url)
				# print("Api Key has ran 4 times.. Changing APi Key..\n")
				time.sleep(1)
			print("WaitTime is " + str(waitime) + " Seconds")
			for i in range(1, waitime):
				print(i, end="\r")
				time.sleep(1)
	except GetOutOfLoop:
		csv_handle.close()
	print("unprocessed url " + str(unprocessed))
	with open('url_unprocessed.txt', 'a+') as f:
		for item in unprocessed:
			f.write("%s\n" % item)