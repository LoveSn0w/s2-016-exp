# s2-016-exp
S2-016 Exploit &amp;&amp; Scanner
1、s2_016.py 文件
这是针对S2-016的exploit程序，使用前先搭建Python运行环境，具体网上搜索即可。
使用方法：
python s2-016.py [target_url] [filename of a  webshell] [shellname at remote host]
例子:
[+]目标:www.xxoo.com 当前路径下有名为webshell.jsp的木马  
[+]命令行执行:python s2-016.py http://www.xxoo.com webshell.jsp system.jsp
目标是www.xxoo.com，要传上去的webshell名字是webshell.jsp（放在当前路径下），system.jsp是传到远程服务器上时，在服务器端的名字

一旦攻击成功，那么就访问http://www.xxoo.com/system.jsp

2、Struts2Scanner.py
s2_016漏洞的批量利用脚本。
给定域名列表（配合Google Hacking）进行扫描探测漏洞主机。
