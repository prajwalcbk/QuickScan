#!/usr/bin/python3
#
#  This is a python based tool to scan for Vulnerabilities in any Web Application 
#  mainly it is focused  to determine the Top10 OWASP Vulnerabilities in web app...


#import libraries 
import os
import re
import sys
import time
import requests
import threading
import urllib.request 
from argparse import *
from attacks import sql
from parsel import Selector
from termcolor import colored
from  urllib.parse import urlparse
from bs4 import BeautifulSoup

from attacks import vulnerable_default_pages as vdp
from attacks import open_redirection as op 
from attacks import xss
from attacks import local_file_inclusion as lfi
from attacks.headers_creation import prepareHeaders

from report_data.generate import *
from report_data.data import server_information

#define variables
url=''
input_url=''
threads=10
output='txt'
cookies=''
validcookie=False
headers = {} 

#banner function
def banner():
	print(colored(""" 
				                                                                    
		    $$$$$                       $$  $$      $$$$$                                        
		   $$   $$  $$   $$  **   $$$$  $$ $$      $$       $$$$   $$$$    $ $$$$$   $ $$$$$    $$$$$  $$ $$$   
		   $$   $$  $$   $$  $$  $$     $$$         $$$$   $$     $$  $$    $$   $$   $$   $$  $$___$  $$$ 
		   $$  $$$  $$   $$  $$  $$     $$ $$          $$  $$     $$  $$    $$   $$   $$   $$  $$      $$ 
  		    $$$$$$   $$$$$   $$   $$$$  $$  $$     $$$$$    $$$$   $$$$$$$  $$   $$   $$   $$   $$$$$  $$
		    	 $$                                                                                         """,'blue'))
	print(colored("""                                                       ( Web Vulnerability Scanner )
							     Author : Prajwal A """,'yellow'))
	print(colored("""						Github : https://github.com/prajwalcbk/Quickscanner""",'white',attrs=['dark']))


#help function
def helper():
		print(colored("USAGE OF THE PROGRAM",'blue'))
		print(colored("--------------------",'yellow'))
		print(colored("         python3 main.py [-u <url>]  [-o <output>] [-c <cookie>] [-p <single_page>] ",'red'))
		print(colored("\n         Ex: python3 main.py -u http://msrit.edu (-p http://msrit.edu/index.php) -o txt -c \"phpsessionid=1234\" ",'green',attrs=['bold']))
		print(colored("\nOPTIONS",'blue'))
		print(colored("-------",'yellow'))
		print(colored('''        -u --url     --> URL of the target website to scan    Ex: http://website.com
	-o --output  --> Output  format of Report to save     Ex: txt html console default(console)
	-c --cookie  --> Cookies after target website login   Ex: "key1=value1;key2=value2" 
	-p --page    --> Single page checking No crawl        Ex: http://website.com/index.html ''','green'))
		print(colored("\n\nINTERACTION",'blue'))
		print(colored('-----------','yellow'))
		print(colored('         CTRL+C to quit the program','green'))
	
		print(colored("\n\nDESCRIPTION",'blue'))
		print(colored("-----------",'yellow'))
		print(colored('''          This is a python based tool to scan for Vulnerabilities in any Web Application 
	  mainly it is focused  to determine the Top OWASP Vulnerabilities in web app...\n''','green'))
		f()



#Overide the error method in ArgumentParser
class MyParser(ArgumentParser):
	def error(self, message):
		print(colored("[-] "+message+'\n','red'))
		helper()
		sys.exit(2)



#Argument passing taking inputs from the terminal
def create_argument_parser():
	try:
		parser=MyParser(add_help=False)
		parser.add_argument('-u','--url',dest='url',required=False)
		parser.add_argument('-o','--output',dest='output',required=False,default='console')
		parser.add_argument('-p','--page',dest='page',required=False,default='')
		parser.add_argument('-c','--cookie',dest='cookies',required=False,default='')#yaml.safe_load)
		return parser.parse_args()
	except Exception as e:
		print(colored(e,'red'))
		helper()


#function to check internet connectivity
#0 stdin 1 stdout 2 stderr
def internet_check():
	try:
		num=os.system('ping -c 1 google.com > internet.txt 2>&1')
		file_pointer=open('internet.txt')
		content=file_pointer.read()
		file_pointer.close()
		os.system('rm internet.txt')
		if not "0% packet loss" in content:
			print(colored('[-] NO INTERNET CONNECT TO NETWORK AND TRY AGAIN','red'))
			print(colored('[+] IF YOU ARE CONNECTED TO NETWORK AND HAVING STABLE CONNECTION PLEASE TRY AGAIN','yellow'))
			f()
			sys.exit(0)
		else:
			print(colored('[+] HAVING STABLE INTERNET CONNECTION','green'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored(e,'red'))
		f()



#function to check given url to valid or notd 
def url_check():
	try:
		global url
		if not re.match(r'http(s?)\:\/\/', url):
			print(colored('[-] ENTER THE CORRECT URL OF THE TARGET','red'))
			f()
			helper()
			sys.exit(0)
		else:
			print(colored('[+] URL IS VALID','green'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored(e,'red'))


def dict_cookie_return(cookies):
	cookies_dict={}
	if(cookies==''):
		return cookies_dict
	else:
		cookie_split=cookies.split(';')
		cookies_dict={}
		for i in cookie_split:
			j=i.split('=')
			k=j[0]
			cookies_dict[k]=j[1]
		return cookies_dict
	
#function to check cookie is valid or not 
def cookie_check():
	try:
		#print(colored(input_url,'red'))
		#print(colored(cookies,'red'))
		global url
		global cookies
		global validcookie
		cookies_dict=dict_cookie_return(cookies)
		response1=requests.get(input_url,cookies=cookies_dict,timeout=5)
		response2=requests.get(input_url,timeout=5)
		global validcookie
		if('Content-Length' in response1.headers and 'Content-Length' in response2.headers):	
			if not (response1.headers['Content-Length']==response2.headers['Content-Length']):
				if(response1.text!=response2.text):
					print(colored("[+] VALID COOKIE",'green'))
					validcookie=True
				else:
					print(colored("[-]INVALID COOKIE",'red')) 
			else:
				print(colored("[-]INVALID COOKIE",'red'))
		else:
			#print(response1.text)
			#print(response2.text)
			if(response1.text!=response2.text):
				print(colored("[+] VALID COOKIE",'green'))
				validcookie=True
			else:
				print(colored("[-] INVALID COOKIE",'red'))
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored(e,'red'))
		print(colored('[-] TARGET IS NOT REACHABLE WITH THAT COOKIE CHECK URL ','red'))

		
	


#function to know target is reachable or not
def host_reachable():
	try:
		global url
		status_code = urllib.request.urlopen(url,timeout=5).getcode()
		if(status_code == 200):
			print(colored('[+] TARGET IS REACHABLE ','green'))
		else:
			print(colored('[-] TARGET IS NOT REACHABLE CHECK URL ','red'))
			f()
			sys.exit(0)
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
		f()
		sys.exit(0)
	except Exception as e:
		print(colored('[-] '+str(e),'red'))
		print(colored('[-] TARGET IS NOT REACHABLE CHECK URL ','red'))
		f()
		sys.exit(0)






#function to gather information about the Target website
def information_gathering():
	try:
		global url 
		information_file_pointer=open('report/server_information.py','w')
		response=requests.get(url,timeout=5)
		if('server' in response.headers):
			print(colored("[+]  SERVER      --> "+response.headers['server'],'green'))
			information_file_pointer.write('Server=\"'+response.headers['server']+'\"\n')
			server_information.Server=response.headers['Server']
		if('X-Powered-By' in response.headers):
			print(colored("[+]  X_Powered_ByPowered_By--> "+response.headers['X-Powered-By'],'green'))
			information_file_pointer.write('X_Powered_By=\"'+response.headers['X-Powered-By']+'\"\n')
			server_information.X_Powered_By=response.headers['X-Powered-By']
		if('Connection' in response.headers):
			print(colored("[+]  CONNECTION   -> "+response.headers['Connection'],'green'))
			information_file_pointer.write('Connection=\"'+response.headers['Connection']+'\"\n')
			server_information.Connection=response.headers['Connection']
		if('Content-Type' in response.headers):
			print(colored("[+]  CONTENT-TYPE -> "+response.headers['Content-Type'],'green'))
			information_file_pointer.write('Content_Type=\"'+response.headers['Content-Type']+'\"\n')
			server_information.Content_Type=response.headers['Content-Type']
		information_file_pointer.write('Url=\"'+url+'\"')
		server_information.Url=url
		information_file_pointer.close()
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
		f()
		sys.exit(0)
	except Exception as e:
		print((colored('[-]'+str(e),'red')))
		print(colored('[-] EXCEPTION OCCURED WHILE GATHERING TARGET INFORMATION ','red'))

#function to spider crawl over the target website 
links_list=[]
target_path=[]
target_links=[]
target_photos=[]
target_photos_dict={}

def spider_links(myurl,cookies='',first=False):
	global links_list , target_photos_dict
	try:
    		if(re.match(r'http(s?).*logout.*',myurl)):
    		#if we logout from the session we will miss some pages
    			return
    		headers=prepareHeaders(cookies)
    		cookies_dict=dict_cookie_return(cookies)
    		if(myurl not in links_list or first==True):
	        	#response=requests.get(myurl,timeout=5,cookies=cookies_dict)
	        	response=requests.get(myurl,timeout=5,headers=headers,cookies=cookies_dict)
	        	#print(colored(headers,'green'))
		        if(response.status_code!=200):
		        	return
		        print(colored("[+] SPIDERING     GOT SOME PAGE  -->  "+myurl,'green'))
		        links_list.append(myurl)
		        if(page==myurl):
		        	return
		        select=Selector(response.text)
		        links=select.xpath('//a/@href').getall()
		        directories=select.xpath('//img/@src').getall()
		        temp=[]
		        for i in directories:
		        	if(len(i)<100 and i not in target_photos):#or re.match(r'data:image/jpeg;base64.*',i)):
		        		target_photos.append(i)
		        		temp.append(i)
		        if(temp!=[]):
		        	target_photos_dict[myurl]=temp
		       #print(target_photos_dict	)
		        links=list(set(links))
		        #print(colored(links,'blue'))
		        #print(response.url)
		        #print(colored(BeautifulSoup(response.content),'yellow'))
		        for link in links:
		        	#if('DVWA' in link):
		        	#	print()
		        	if(len(link)<=0):
		        		continue
		        	#link=link.strip('/')
		        	#print(link)
		        	if 'javascript:' in link or 'mailto' in link:
		        		continue
		        	if re.match(r'#.*',link):
		        		#no need to check for fragments so skip
		        		continue
		        	if urlparse(link).netloc!='' or '.com' in link:
		        		if(re.match(r'http(s?).*\.com',urlparse(link).netloc) or re.match(r'.*\.com',link)):#urlparse(link).netloc)):
		        		#illgeal to do crawl on .com websites
		        			print(colored('[-].COM WEBSITE GOT SKIP         -->  '+link,'white',attrs=['dark']))	
		        			#print(colored('[-]                              --> '+link,'red'))
		        			continue
		        	if re.match(r'http(s?).*\.in',link):
		        		#illgeal to do crawl on .in websites
		        		print(colored('[-].IN WEBSITE GOT SKIP          -->  '+link,'white',attrs=['dark']))
		        		continue
		        	if re.match(r'http(s?).*\.pdf',link) or re.match(r'http(s?).*\.PDF',link) or '.pdf' in link:
		        		#If we got pdf link then no crawl
		        		print(colored('[-].PDF FILE GOT SKIP            -->  '+link,'white',attrs=['dark']))
		        		continue
		        	if re.match(r'http(s?).*\.jpg',link) or re.match(r'http(s?).*\.jpeg',link) or re.match(r'http(s?).*\.png',link) or re.match(r'.*\.png',link):
		        		#if we got jpg files then no need to crawl
		        		print(colored('[-] IMAGE FILE GOT SKIP          -->  '+link,'white',attrs=['dark']))
		        		continue
		        	if re.match(r'http(s?)\:\/\/.*',link):
		        		if not re.match(url+'.*',link):
		        			print(colored('[-] GOT SOME OTHER WEBSITE LINK  -->  '+link,'white',attrs=['dark']))
		        			continue
		        	if not re.match(r'http(s?)\:\/\/',link):
		        		#If we got link with protocol and path no need to add any thing 
		        		#if re.match(r'.*.com')
		        		#print(myurl)
		        		#print(colored(link,'blue'))
		        		if(len(link)>=2):
		        			if(link[0]=='.' and link[1]=='/' ):
		        				link=link[2:]


		        		if(link[0]=='/'):
		        			#print(colored(link[0],'blue'))
		        			link=url+link
		        		
		        		else:
		        			#print('url --> ',url)
		        			#print('response_url --> ',response.url)
		        			#print('link --> ',link)
			        		u_link_parse=urlparse(response.url).path
			        		u_link_parse=u_link_parse.lstrip('/')
			        		u_link_parse=u_link_parse.split('/')
			        		count=len(u_link_parse)
			        		if('../' in link):
			        			counter=link.count('../')
			        			link=link.strip('../')
			        			if(counter==1):
			        				link=url+'/'+link
			        			elif(counter>=2):
			        				temp_link=url
			        				for i in range(counter-2):
			        					temp_link+='/'+u_link_parse[i]
			        				link=temp_link+'/'+link
			        		elif(count==0 or count==1):
			        			link=url+'/'+link
			        		elif(count>=2):
			        			extra_link=url
			        			for i in range(count-1):
			        				extra_link+='/'+u_link_parse[i]
			        			link=extra_link+'/'+link

		        	if(link in links_list):
		        		#if it is already crawled then no need to do once more
		        		continue
		        	print(colored('[*] SPIDER FOR LINK              -->  '+link,'yellow'))
		        	spider_links(link,cookies)
	except Exception as e:
		print(colored(e,'red'))
		print(colored(links,'blue'))
		pass

	


#function to print the link which we are targeting
def print_target_links():
	try:
		print(colored('[+] PAGES GOT AFTER SPIDERING AND CRAWLING ','yellow'))
		#for i in links_list:
			#print(colored('     '+i,'blue'))
		global links_list , target_links
		links_list=list(set(links_list))
		print(colored('[*] TARGET LINKS STORED INSIDE   --> target.txt(Inside report)','cyan',attrs=['bold']))
		for i in links_list:
			single_link_parsing=urlparse(i)
			if(single_link_parsing.query):
				query_url=single_link_parsing.query
				query_list=query_url.split('&')
				for k in query_list:
					i1=k.split('=')
					if(i1[1].isnumeric() and single_link_parsing.path in target_path):
						break
				else:
					if(single_link_parsing.path+'?'+single_link_parsing.query not in target_path):
						target_path.append(single_link_parsing.path)
						target_links.append(i)
			elif(single_link_parsing.path+'?'+single_link_parsing.query not in target_path):
				target_path.append(single_link_parsing.path)
				target_links.append(i)
		target_file=open('report/target.txt','w')
		for j in target_links:
			target_file.write(j+'\n')
			print(colored('[!!] WE CAN TARGET ON THIS LINK  -->  '+j,'red',attrs=['dark','bold']))
		target_file.close()
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
		f()
		sys.exit(0)
	except Exception as e:
		print((colored('[-]'+str(e),'red')))


screen=170
def f(s=screen):
	print()
	#print('       ',end='')
	#print(colored(''*s,'white',attrs=['dark']))#,'on_grey',attrs=['dark']))


#main function 
def main():
	try:
		global cookies,url,target_photos_dict,validcookie
		f()
		print(colored('[*] CHECKING FOR INTERNET CONNECTION','yellow'))
		internet_check()
		f()
		print(colored('[*] CHECKING VALID URL OR NOT ','yellow'))
		url_check()
		f()
		print(colored('[*] CHECKING TARGET IS REACHABLE OR NOT','yellow'))
		host_reachable()
		f()
		if not (cookies==''):
			print(colored("[*] CHECKING VALID COOKIE OR NOT ",'yellow'))
			cookie_check()
			f()
		print(colored('[*] GATHERING INFORMATION ABOUT THE TARGET','yellow'))
		information_gathering()
		f()
		f()
		print(colored('[!] DO YOU WANT TO CRAWL THE WEBSITE FROM GIVEN URL TYPE [Y/n]','blue'),end='\n')
		yes_or_no=input()
		print(colored('[!] DO YOU WANT TO CRAWL THE WEBSITE FROM THIS URL '+url+'  [y/N]','blue'),end='\n')
		yes_or_no_index_crawl=input()
		if(yes_or_no_index_crawl=='Y' or yes_or_no_index_crawl=='y'):
			print(colored('[*] SPIDERING AND WEB CRAWLING THE TARGET WEBSITE','yellow'))
			spider_links(url,cookies)
			if(validcookie==True):
				spider_links(input_url,first=True)
		if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
			print(colored('[*] SPIDERING AND WEB CRAWLING THE TARGET WEBSITE','yellow'))
			spider_links(input_url,cookies)
			sys.setrecursionlimit(2000)
			if(validcookie==True):
				spider_links(input_url,first=True)
			f()
			print_target_links()
			f()
			print(colored('[!!] GOT SOME IMAGES INSIDE WEBSITE ','yellow'))
			print(colored('[*] SOME IMAGES OUTSIDE WEBSITES -->  photos.txt(links stored in this file)','cyan',attrs=['bold']))
			link_file_pointer=open('report/internet_photos.txt','w')
			link_file_pointer_local=open('report/local_photos.txt','w')
			for photos in target_photos_dict:
				for photos_photos in target_photos_dict[photos]:
					#print(photos_photos)
					if (re.match(r'http(s?).*',photos_photos)):
						link_file_pointer.write(photos_photos+'\n')
						continue #we have to include this in report 
					else:
						link_file_pointer_local.write(photos_photos+'\n')
						print(colored('[!] SOME IMAGES INSIDE WEBSITE   -->  '+photos_photos,'red'))
			link_file_pointer.close()
			link_file_pointer_local.close()
			f()
		else:
			f()
		try:
			try:
				print(colored('[!] NEXT MODULE CHECKING FOR SQL INJECTION ','yellow'))
				print(colored('[!] DO YOU WANT TO CHECK FOR SQL INJECTION TYPE [Y/n]','blue'),end='\n')
				yes_or_no=input()
				if(yes_or_no=='Y'or yes_or_no=='' or yes_or_no=='y'):
					print(colored('[*] CHECKING TARGET WEBSITES FOR SQL INJECTION ','yellow'))
				#print(cookies)
					try:
						for i in target_links:
							u=urlparse(i)
							headers=prepareHeaders(cookies)
							if(len(u.path)==0):
								continue
							t=threading.Thread(target=sql.scan_sql_injection,args=(i,headers))
							t.start()
						try:
							time.sleep(2)
							print(colored('\r[*] WAITING FOR THREADS TO COMPLETE TASK','magenta',attrs=['bold']),end='')
							time.sleep(2)
							f()
						except:
							pass
					except:
						pass
			except KeyboardInterrupt:
				f(screen-2)
				print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING SQL INJECTION CHECKING','red',attrs=['bold']))
			except Exception as e:
				print(colored(e,'red'))	
			print('\r',flush=True,end='')
			f()
			try:
				print(colored('[!] NEXT MODULE CHECKING FOR CROSS SITE SCRIPTING VULNEARBILITY ','yellow'))
				print(colored('[!] DO YOU WANT TO CHECK FOR CROSS SITE SCRIPTING VULNEARBILITY  [Y/n]','blue'),end='\n')
				yes_or_no=input()
				if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
					print(colored('[*] CHECKING TARGET WEBSITES FOR CROSS SITE SCRIPTING ','yellow'))
					for i in target_links:
						headers=prepareHeaders(cookies)
						t=threading.Thread(target=xss.scan_xss,args=(i,headers))
						t.start()
					try:
						time.sleep(3)
						print(colored('\r[*] WAITING FOR THREADS TO COMPLETE TASK','magenta',attrs=['bold']),end='')
						time.sleep(2)
						f()
					except:
						pass	
			except KeyboardInterrupt:
				f(screen-2)
				print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING XSS CHECKING','red',attrs=['bold']))
			except Exception as e:
				print(colored(e,'red'))	
			print('\r',flush=True,end='')
			f()
			try:
				print(colored('[!] NEXT MODULE CHECKING FOR SERVER MISCONFIGURATIONS ','yellow'))
				print(colored('[!] DO YOU WANT TO CHECK FOR DEFAULT VULNEARBLE WEB PAGES TYPE [Y/n]','blue'),end='\n')
				yes_or_no=input()
				if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
					print(colored('[*] CHEKING TARGET WEBSITE FOR DEFAULT VULNEARBLE PAGES','yellow'))
					headers=prepareHeaders(cookies)
					vdp.vulnerable_pages(url,headers)
					try:
						time.sleep(0.5)
						print(colored('\r[*] WAITING FOR THREADS TO COMPLETE TASK','magenta',attrs=['bold']),end='')
						time.sleep(2)
						f()
					except:
						pass
					#print('\r',flush=True,end='')
			except KeyboardInterrupt:
				f(screen-2)
				print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING VULNEARBLE PAGES CHECKING ','red',attrs=['bold']))
			except Exception as e:
				print(colored(e,'red'))	
			print('\r',flush=True,end='')
			f()
			try:
				print(colored('[!] NEXT MODULE CHECKING FOR OPEN REDIRECTION VULNEARBILITY ','yellow'))
				print(colored('[!] DO YOU WANT TO CHECK FOR OPEN REDIRECTION [Y/n]','blue'),end='\n')
				yes_or_no=input()
				if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
					print(colored('[*] CHECKING TARGET WEBSITES FOR OPEN REDIRECTION ','yellow'))
					for i in target_links:
						if(urlparse(i).query):
							headers=prepareHeaders(cookies)
							t=threading.Thread(target=op.scan,args=(i,headers))
							break_yes_no=t.start()
							if(break_yes_no=='quit'):
								break
					try:
						time.sleep(0.5)
						print(colored('\r[*] WAITING FOR THREADS TO COMPLETE TASK','magenta',attrs=['bold']),end='')
						time.sleep(2)
						f()
					except:
						pass
				#print('\r',flush=True,end='')
			except KeyboardInterrupt:
				f(screen-2)
				print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING OPEN REDIRECTION CHECKING ','red',attrs=['bold']))
			except Exception as e:
				print(colored(e,'red'))	
			print('\r',flush=True,end='')
			f()
			try:
				print(colored('[!] NEXT MODULE CHECKING FOR LOCAL FILE INCLUSION VULNEARBILITY ','yellow'))
				print(colored('[!] DO YOU WANT TO CHECK FOR LOCAL FILE INCLUSION [Y/n]','blue'),end='\n')
				yes_or_no=input()
				if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
					headers=prepareHeaders(cookies)
					print(colored('[*] CHECKING TARGET WEBSITES FOR LOCAL FILE INCLUSION  ','yellow'))
					lfi_paths=[]
					for i in target_links:
						if(urlparse(i).query):
							if not(urlparse(i).path in lfi_paths):
								lfi_paths.append(urlparse(i).path)
								t=threading.Thread(target=lfi.main,args=(i,headers))
								break_yes_no=t.start()
							if(break_yes_no=='quit'):
								break
					try:
						time.sleep(2)
						print(colored('\r[*] WAITING FOR THREADS TO COMPLETE TASK','magenta',attrs=['bold']),end='')
						time.sleep(2)
						f()
					except:
						pass
				#print('\r',flush=True,end='')
			except KeyboardInterrupt:
				f(screen-2)
				print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING OPEN REDIRECTION CHECKING ','red',attrs=['bold']))
			except Exception as e:
				print(colored(e,'red'))
			print('\r',flush=True,end='')
			f()
		except Exception as e:
			print(colored(e,'red'))
	except KeyboardInterrupt:
		f(screen-2)
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED ','red',attrs=['bold']))
	except Exception as e:
		print(colored(e,'red'))


#starting point of Code
if __name__=='__main__':
	try:
		start_time=time.time()
		os.system('rm -r report > error.logs 2>&1; mkdir report > error.logs 2>&1')
		banner()
		print('\n')
		parser=create_argument_parser()
		if(parser.url==None and parser.page==''):
			print(colored("[-] Enter Url or Website Page of the target \n",'red',attrs=['bold']))
			helper()
			sys.exit(0)
		else:
			page=parser.page
			#print(page)
			if(page!=''):
				url=page
				input_url=page
				input_url=input_url.rstrip('/')
				if(page[-1]=='/'):
					page=page[:-1]
			else:
				url=parser.url
				input_url=url
				input_url=input_url.rstrip('/')
				urlparsed=urlparse(url)
				url=urlparsed.scheme+'://'+urlparsed.netloc
			if (url[-1]=='/'):
				url=url[:-1]
			#print('url --> ',url)
			if(not(parser.output=='txt' or parser.output=='html' or parser.output=='console')):
				helper()
				sys.exit(0)
			output=parser.output
			cookies=parser.cookies
			headers=prepareHeaders(cookies)
			
		main()
		print(colored('\r[!] DO YOU WANT TO CREATE REPORT [Y/n]','blue'),end='\n')
		yes_or_no=input()
		if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
			print(colored('[*] CREATING OUTPUT REPORT PLEASE WAIT ','yellow'))
			create_target_links()
			create_photos_links()
			create_internet_photos_links()
			create_main_report()
			#merge_pdf()
			print(colored('[+] GENERATED REPORT SUCCESSFULLY (Inside ./report/)','green',attrs=['bold']))
		end_time=time.time()
		f()
		print(colored('\r[!] DO YOU WANT TO OPEN REPORT [Y/n]','blue'),end='\n')
		yes_or_no=input()
		if(yes_or_no=='Y' or yes_or_no=='' or yes_or_no=='y'):
			os.system('firefox report/Quick_Scanner_generated_report.html &')
		#print('sql.sql_list=',sql.sql_list)
		#print('xss.xss_list',xss.xss_list)
		#print('op.open_redirection_list',op.open_redirection_list)
		#print('vdp.vulnerable_pages_list',vdp.vulnerable_pages_list)
		time.sleep(0.5)
		f()
		print(colored('[**] TIME TAKEN TO EXECUTE THE CODE '+str(end_time-start_time)+ " SECONDS",'yellow','on_grey',attrs=['bold','reverse']))
		f()
	except KeyboardInterrupt:
		f()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED QUITING ','red',attrs=['bold']))
		f()
	except Exception as e:
		print(colored(e,'red'))
