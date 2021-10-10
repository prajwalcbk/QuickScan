import requests
from termcolor import colored
from urllib.parse import urlparse

screen=170
open_redirection_list=[]
#design function 

def f(s=screen):
    #print('       ',end='')
    print(colored(' '*s,'white','on_grey',attrs=['dark']))


def scan(url,headers):
    print(colored('\r[!] TRYING OPEN REDIRECTION VULNERABILITY LINK  -->  '+url,'white',attrs=['dark']),flush=False,end='\n')
    open_redirection_file_pointer=open('payloads/open_redirection.txt','r')
    for payload in open_redirection_file_pointer.readlines():
        payload = payload.strip('\n')
        try:
            op_url_parsed=urlparse(url)
            target=op_url_parsed.scheme+'://'+op_url_parsed.netloc+op_url_parsed.path+'?'
            #target=url+payload
            for query in op_url_parsed.query.split('&'):
                query_list=query.split('=')
                target+=query_list[0]+'='+payload+'&'
            target=target.rstrip('&')
            target+=op_url_parsed.fragment
            #print(colored('\r[!] TRYING OPEN REDIRECTION VULNERABILITY LINK  -->  '+target,'white',attrs=['dark']),flush=False,end='\n')
            try:
                res=requests.get(target,headers=headers)
                if(res.status_code!=404 and op_url_parsed.netloc not in res.url ):
                    for response in res.history:
                        if response.status_code == 301 or response.status_code == 302:
                              print(colored("\n[+] OPEN REDIRECTION VULNERABILITY EXISTS FOR THIS PAGE WITH PAYLOAD -->  "+target+'\n','red',attrs=['bold']))
                              open_redirection_list.append(target)
                              return
            except KeyboardInterrupt:
                f(screen-2)
                print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING OPEN REDIRECTION CHECKING ','red',attrs=['bold']))
                return 'quit'
            except:
                pass
        except Exception as e:
            print(colored('[-] Exception --> '+str(e),'red'))
