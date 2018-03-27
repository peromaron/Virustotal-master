#coding:utf-8
#json形式
#APIにアクセスするため
#mysql.connectorを使用

import json as _json
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import sys
import time 
import mysql.connector
import datetime
from pprint import pprint

from urllib.request import Request, urlopen

#Apikeyを設定
class Apikey:
	def __init__(self):
		#database接続
		self.connect = mysql.connector.connect(user='root', password='', host='localhost', database='kaiseki_development', charset='utf8')
		self.connect.autocommit = True
		self.cursor = self.connect.cursor()
		self.cursor.execute('use kaiseki_development')
		
		#virustotal_api_keysの中身を空に
		self.cursor.execute('truncate table virustotal_api_keys')
		#apikey
	def set_apikeys(self):
		apikeys = ['"c2d51ce4334a95e2e44737bd2d8314622f13f64476897511a4df73cb97a20ae5"',
					'"8b5ca79ac811520579a3aa6d5ccc4b57562ce5acb524e5eaf4ea7648eb717323"',
					'"317f79daf07d3b9efda79d246fbc6563a6a30f02fe8e2cce102ae0c9b36ee8b"',
					'"e5320e38bb9c115cf1e21bca158383f1b110cb56aca704700053b0bd0fda9c7c"',
					'"e62c860e26ef0df7e25e122112c619fb3013da4b5f23e00b81b1a7a0f9a1bb22"',
					'"e568c6801bdb0ec3a2ec493442cddef974f5be35839b63ef5e2650ceb62f77a4"',
					'"f2fdeef61b033e64a96d22ab22f409dbf99a68c4d07611c801e4f3044afaad89"',
					'"e395da8c3345f48e380d008cd41e822efd696938dd528e337d7f10cdde1fbfa9"',
					'"f3ef143791f7461fd04b9d891a4c3ec50ceca612006017d6bb5e96ec08c78d21"',
					'"5fbf11633d2aea4add98b880873f9cc06e50e704c58b8d112920d94850327d8e"',
					'"6372440a066053ceda3e6b451be2fe3aeda3cc74d605ce763b30c8d237287660"',
					'"992255a17799eb7b7bb7dd0d55d094ae052efcda13722b86572ebc372b39165c"',
					'"5e047b97a43200bc3d3df7ba6c5749f0c8f199c2d5ea44df424d31ca2341b482"',
					'"390ce49093c9e43500ca0dabe5fdd68622ee00622a4ef901b41c7368ed539e98"',
					'"4cfc68108f9d838fb41ec02efb3593b61eb48eca0652c21a46f2f3f1641e52a0"',
					'"1b00ae7aeb315a48cd83063338932ba4b17273eed78c9707fc3ec35953413ee7"',
					'"02def11b43160fd83719386fe7d9f1d724ed52d9accc0d1bc4e0d2e9811112bd"',
					'"c7dbe67db5ae9546434e5464f305a46be493816b7bca85c1d68b52fd06e62490"',
					'"2173cd1c2a97c7d23d6d78b6ab16a42b3a20cf97b595f97ce489f8bff9e71836"',
					'"ab099f9e1875ea476818ad1e69a600704e769dd189e2f4ef6a4e7783714a9ce2"',
					'"bbd9f2a438418d148071dcee1b3ada1f06055bceb7d4aa56665d2e113b14ed1a"',
					'"6c791140b269f77742420ff75583229768364cef5e8e6ce903786e7d88270d1a"',
					'"1253922fd80adbaa367a3050b16b030d68b7ab403444e7dcb4915600bc067b48"',
					'"415e3ec74974ea4f69f2a9fd8d2e471cee1a102c1d6b4f660519db2e2f2e2725"',
					'"e70b2f866898c5537013e3f0a63aef672dcb6d1a5ab17e1b258236e34aee16c6"'] 

		for n in range(len(apikeys)):
			#table virustotal_api_keysのapi_key,use_time,use_numbers,created_at,updated_atに追加	
			self.cursor.execute('insert into virustotal_api_keys(api_key,use_time,use_numbers,created_at,updated_at) values(%s,now(),0,now(),now())' % (apikeys[n]))

			

#Analysisを設定
class Analysis:
	def __init__(self,analysis_id,analysis_url):
		#database接続
		self.connect = mysql.connector.connect(user='root', password='', host='localhost', database='kaiseki_development', charset='utf8')
		self.connect.autocommit = True
		self.cursor = self.connect.cursor(buffered=True)
		self.analysis_id = analysis_id
		self.url = analysis_url
		self.cursor.execute('use kaiseki_development')
		


		self.analyse_url = "https://www.virustotal.com/vtapi/v2/url/scan"

	def virustotal(self):
		#self.url = str(self.analysis_url)
		#self.url = str(self.cursor.execute('select short_url from short_urls where id = + %d' % (self.analysis_id)))
		#現在の時間
		now = datetime.datetime.now()

		self.cursor.execute('select Max(id) from virustotal_api_keys')

		record = self.cursor.fetchone()
		
		mMax = record[0]

		#idの最大値をVirustotal_api_keysから取得
		for m in range(mMax):
			
			#now.minuteとuse_timeが一緒
			self.cursor.execute('select use_time from virustotal_api_keys where id = %d' % (m+1))
			

			if str(now.minute) == str(record[0]):

				#この分に使った回数が4回かrecord = self.cousor.fetchone()
				self.cursor.execute('select use_numbers from virustotal_api_keys where id = %d ' % (m+1))
				record = self.cursor.fetchone()

				if int(record[0]) == 4:

					#今見ているidが最大値を満たしているか
					if m + 1 == mMax: 
						time.sleep(60)
						#sleepしたらidの探索を元に戻す
						m = -1
					continue
				else: break 
			else:
				self.cursor.execute('update virustotal_api_keys set use_numbers = 0 where id = %d' % (m+1))		
				break	 	

		self.cursor.execute('select api_key from virustotal_api_keys where id = %d' % (m+1));
		record = self.cursor.fetchone()
		self.apikey = str(record[0])	
		self.__calc()
		#table virustotal_api_keysのuse_time,use_numbersにnow,use_number+1をして格納
		self.cursor.execute('update virustotal_api_keys set use_time = now(),use_numbers = use_numbers + 1 where id = %d' % (m+1))

	def __calc(self):

		now = datetime.datetime.now()
		targeturl = self.url
		url = self.analyse_url
		apikey = self.apikey

		
		#parameters = urllib.parse.urlencode({"apikey": apikey,"targeturl": self.url}).encode("utf-8")
	
		#response = urllib.request.urlopen("https://www.virustotal.com/vtapi/v2/url/scan", data=parameters)

		#json = _json.loads(response.read().decode('utf-8'))

		#deta = 3

		#pprint("json:" + str(json["scan_date"]))

		#if not json:
			#print("Error in calling /url/scan API")
			#return 1

		#scan_id = json["scan_id"]

		#print("Wait 10 seconds...")
		#time.sleep(10)

		print("Waiting response 'GET /url/report'")

		query = urllib.parse.urlencode({"apikey": self.apikey, "resource":targeturl})

		response = urllib.request.urlopen("https://www.virustotal.com/vtapi/v2/url/report?" + query)

		json = _json.loads(response.read().decode('utf-8'))

		pprint("positives:" + str(json["positives"]))

		pprint("total:" + str(json["total"]))

		x_1 = (json["positives"] /	int(json["total"]))

		x_2 = round(x_1)

		pprint("x_1:" + str(x_1) + " x_2:" + str(x_2))

		#print (["positives"])
		#short_url_id = 2610
		sql = 'insert into analysis_results (short_url_id,search_url,search_time,analysis_result,updated_at) values(%d,\"%s\",\"%s\",%d,\"%s\")'% (self.analysis_id,targeturl,now, x_2, now)
		print(sql)
		self.cursor.execute(sql)

		if not json:
			print("Error in calling /url/report API")
			return 2

		return 0

	

if __name__ == "__main__":
	sys.exit(main())        
		#print (["positives"])
		#m2 = "url"	
		#print(decjson["m2"])


	#sql = ('update analysis_results set search_time = %s, analysis_result = %d, updated_at = %s' % (now, x_2, now))
	#print(sql)
		#self.cursor.execute('update analysis_results set search_time = %s, analysis_result = %d, updated_at = %s' % (now, x_2, now))