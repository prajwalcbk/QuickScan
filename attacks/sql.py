import requests as s
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from termcolor import colored
from  urllib.parse import urlparse


sql_list=[]
def get_all_forms(url,headers):
    """Given a `url`, it returns all forms from the HTML content"""
    try:
    	soup = bs(s.get(url,headers=headers).content, "html.parser")
    	return soup.find_all("form")
    except Exception as e:
    	print(colored(e,'red'))
    

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action")
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    #type=button , submit , textarea , option 
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    for textarea_tag in form.find_all('textarea'):
        input_name=textarea_tag.attrs.get('name')
        input_value=textarea_tag.attrs.get('value')
        if not (input_value):
            input_value=''
        input_type='text'
        if  (input_name):
            inputs.append({"type":input_type,"name": input_name,"value":input_value})
    for button_tag in form.find_all('button'):
        input_name=button_tag.attrs.get('name')
        input_value=button_tag.attrs.get('value')
        input_type=button_tag.attrs.get('type')
        if(input_type.lower()=='submit' and input_name):
            inputs.append({"name": input_name,"value":input_value})
    for select in form.find_all('select'):
        input_name=select.attrs.get('name')
        for option in select.find_all('option'):
            if(option.attrs.get('name')):
                input_value=option.attrs.get('name')
                break
        if  (input_name):
            inputs.append({"name": input_name,"value":input_value})


    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
        'Error: You have an error in your SQL syntax'
    }
    #print(bs(response.content))
    for error in errors:
        if error in response.text.lower():
            return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url,headers):
    global sql_list , sql_count
    #sql_file_pointer.write('sql_injections=[')
    for c in "\"'":
        u=urlparse(url)
        urlparsed_query=urlparse(url).query
        urlparsed_query=urlparsed_query.replace('&',f"{c}&")
        url_temp=u.scheme+'://'+u.netloc+u.path+u.params
        if(u.query):
            url_temp+='?'+u.query
        url_temp+=u.fragment
        new_url = f"{url_temp}{c}"

        print(colored("[!] TRYING FOR SQL INJECTION LINK  -->  "+url,'white',attrs=['dark']),flush=False,end='\n')
        res = s.get(new_url,headers=headers)
        if is_vulnerable(res):
            print(colored("\n[+] SQL INJECTION VULNERABILITY DETECTED GET  TYPE LINK  -->  "+str(new_url)+'\n','red',attrs=['bold']))
            #sql_file_pointer.write("{ 'url':'"+new_url+"','method':'get'}")
            sql_dict={'url':url,'method':'get','attacked_url':new_url,'payload':urlparse(new_url).query}
            sql_list.append(sql_dict)
            #print(sql_list)
            return
    forms = get_all_forms(url,headers)
    #print(colored(f"[+] Detected {len(forms)} forms on {url}.",'yellow'))
    for form in forms:
        form_details = get_form_details(form)
        #print(colored(form_details,'red'))
        for c in "\"'":
            # the data body we want to submit
            data = {}
            #print(colored(form_details['inputs'],'blue'))
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            #print(colored(data,'yellow'))
            main_url=url
            url = urljoin(url, form_details["action"])
            #print(colored(url,'white'))
            if form_details["method"] == "post":
                res = s.post(url, data=data,headers=headers)
                if is_vulnerable(res): 
                    print(colored("\n[+] SQL INJECTION VULNERABILITY DETECTED POST TYPE LINK  -->  "+str(url)+'\n[*] DATA : POST TYPE  --> '+str(data)+'\n','red',attrs=['bold']))
                    sql_dict={'url':main_url,'method':'post','attacked_url':url,'payload':data}
                    sql_list.append(sql_dict)
                    #print(sql_list)
            elif form_details["method"] == "get":
                res = s.get(url, params=data,headers=headers)
                if is_vulnerable(res):
                    sql_dict={'url':main_url,'method':'get','attacked_url':url,'payload':data}
                    sql_list.append(sql_dict)
                    #print(sql_list)
                    print(colored("\n[+] SQL INJECTION VULNERABILITY DETECTED GET TYPE LINK  -->  "+str(res.url)+'\n[*] DATA : GET TYPE  --> '+str(data)+'\n','red',attrs=['bold']))
    

