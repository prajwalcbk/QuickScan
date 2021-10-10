# QuickScanner

![alt text](https://github.com/prajwalcbk/QuickScan/blob/main/git_photos/logo.jpg)

A Simple Quick Scanner tool build using python to detect Vulnerabilities inside a website.

It mainly focused to detect following Vulnerabilities
* SQL injections
* Cross Site Scripting
* Open Redirection  
* Default Vulnerable pages
* Local File Inclusion


Initially It crawls over the Entire website and prepare a list of target links to attack and 
it will start checking for vulnerabilities using some payloads and later by analysing the response 
it will alert if any vulnerability found.
    
Finally it will Generate report after scanning all the Web pages inside the targets Url.

# Requirements : 
* Python3
* ping (net-tools)
* requests
* termcolor
* bs4
* parsel
* dominate

# Installation
    git clone https://github.com/prajwalcbk/QuickScan

    cd Quickscanner

    pip install -r requirements.txt

# Usage
    python3 main.py

    python3 main.py [-u <url>]  [-o <output>] [-c <cookie>] [-p <single_page>] 
```
  Ex: python3 main.py -u http://msrit.edu [-p http://msrit.edu/index.php] -o console -c "phpsessionid=123" 
```


### Options

| Short form | Long form | Description | Example | 
| --- | --- | --- | --- |
| -u | --url | URL of the target website to scan | http://website.com |
| -o | --output | Output  format of Report to save | txt, html, console default(console) | 
| -c | --cookie | Cookies after target website login | "key1=value1;key2=value2" |  
| -p | --page  | Single page checking No crawl | http://website.com/index.html |

#
![Usage Photo Failed to Show](https://github.com/prajwalcbk/QuickScan/blob/main/git_photos/usage_photo.jpg)

# Working Demo
![Example of Working](https://github.com/prajwalcbk/QuickScan/blob/main/git_photos/work.gif?raw=true "Example of Working")

# Report Generation
### Report on Dvwa by QuickScanner
- https://github.com/prajwalcbk/QuickScan/blob/main/git_photos/Quick_Scanner_Report_on_Dvwa.pdf
