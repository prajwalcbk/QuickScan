#!/usr/bin/pyton3
from termcolor import colored
from  urllib.parse import urlparse
import requests
import threading

vulnerable_pages_list=[]


def test(url,line,file_pointer_default,headers):
	global  vulnerable_pages_list
	try:
		print(colored('[!] TRYING FOR VULNEARBLE PAGE --> '+url+'/'+line,'white',attrs=['dark']),flush=False,end='\n')
		#time.sleep(0.1)
		res=requests.get(url+'/'+line,headers=headers)
		if(res.status_code==200):
			print(colored('\n[+] FOUND VULNEARBLE PAGE (DEFAULT PAGE) --> '+url+'/'+line+'\n','red',attrs=['bold']))
			file_pointer_default.write(url+'/'+line+'\n')
			vulnerable_pages_list.append(url+'/'+line)
	except Exception as e:
		print(colored("[!] PAGE NOT FOUND -->"+url+'/'+line,'red'),flush=False,end='\n')
		print(e)
	
#/usr/share/wordlists/dirb/vulns
def vulnerable_pages(url,headers):
	try:
		urlparsed=urlparse(url)
		url=urlparsed.scheme+'://'+urlparsed.netloc
		file_pointer=open('payloads/vulnerable_default_pages.txt')
		file_pointer_default=open('report/default_vulnerable_pages.txt','w')
		reading_file=file_pointer.readlines()
		for line in reading_file:
			line=line.strip('\n')
			t=threading.Thread(target=test,args=(url,line,file_pointer_default,headers))
			t.start()
			
	except KeyboardInterrupt:
		print()
		print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING DEFAULT VULNEARBLE PAGE CHECKING ','red',attrs=['bold']))
	except Exception as e:
		print((colored('[-]'+str(e),'red')))