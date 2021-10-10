from threading import Thread
import dominate
#import pdfkit
from dominate.tags import *
#from PyPDF2 import PdfFileMerger, PdfFileReader
import sys
#from data import *
from report_data.data import description
from report_data.data import links
from report_data.data import prevention_methods
from report_data.data import server_information

import sys
sys.path.append('../')

from attacks.sql import *
from attacks.xss import *
from attacks.open_redirection import *
from attacks.vulnerable_default_pages import * 
from attacks.local_file_inclusion import *



vulnerability_levels=['High','medium','Low','Information']

sqli_heading=['High','SQL Injection']
xss_heading=['Medium','Cross Site Scripting']
vulnerable_pages_heading=['Low', 'Server Misconfigurations | Default Pages']
local_file_inclusion_heading=['High', 'Local file Inclusion']
open_redirection_heading=['Medium','Open Redirection']

high_count=0
medium_count=0
low_count=0
information_count=0




vulnerability_table_info=['Risk Level','Number of vulnerabilities']


#sql_list= [{'url': 'http://172.17.0.3/vulnerabilities/sqli/', 'method': 'get_form', 'attacked_url': 'http://172.17.0.3/vulnerabilities/sqli/', 'payload': {'id': "test'", 'Submit': "Submit'"}}, {'url': 'http://172.17.0.3/vulnerabilities/brute/', 'method': 'get_form', 'attacked_url': 'http://172.17.0.3/vulnerabilities/brute/', 'payload': {'username': "test'", 'password': "test'", 'Login': "Login'"}}]
#xss_list=[{'url': 'http://172.17.0.2/signup.php', 'method': 'post', 'payload': "';alert('amith');'", 'data': {'Uname': "';alert('amith');'"}}]
#open_redirection_list=[]
#vulnerable_pages_list=['http://172.17.0.2/phpmyadmin', 'http://172.17.0.2/server-info', 'http://172.17.0.2/phpinfo.php', 'http://172.17.0.2/server-status']





def create_target_links():
	urldoc = dominate.document(title="Target URL'S | Quick Scanner")
	with urldoc.head:
		link(rel='preconnect', href='https://fonts.gstatic.com')
		link(href='https://fonts.googleapis.com/css2?family=Do+Hyeon&display=swap', rel='stylesheet')
		link(rel='stylesheet', href='../report_data/style.css')
		link(rel='icon', type='image/x-icon', href="../report_data/favicon.png")
	with urldoc:
		h1("Quick Scanner")
		h2("Scanning report")
		h4("Target Url's",cls='h4-turl')
		target_urls_file_pointer=open('report/target.txt')
		target_urls=target_urls_file_pointer.readlines()
		with table(cls = 't1 t1-Turls'):
			with thead():
				with tr():
					th('URL Web pages Inside target')
			with tbody():
					with tr():
						with td().add(ol()):
							for i in target_urls:
								i=i.strip('\n')
								li(p(a(i, href= i)))
		with b(cls='btn'):
			a("Go Back", href='Quick_Scanner_generated_report.html')
		h5("Generated automaticly by Quick Scanner")
	with open("report/Quick_Scanner_targeted_urls.html", "w") as html_file:
		html_file.write(urldoc.render())
#	pdfkit.from_file('report/Quick_Scanner_targeted_urls.html', 'report/qs2.pdf')


def create_photos_links():
	urldoc = dominate.document(title="Target URL'S | Quick Scanner")
	with urldoc.head:
		link(rel='preconnect', href='https://fonts.gstatic.com')
		link(href='https://fonts.googleapis.com/css2?family=Do+Hyeon&display=swap', rel='stylesheet')
		link(rel='stylesheet', href='../report_data/style.css')
		link(rel='icon', type='image/x-icon', href="../report_data/favicon.png")
	with urldoc:
		h1("Quick Scanner")
		h2("Scanning report")
		h4("Local Images",cls='h4-localimg')
		local_images_file_pointer=open('report/local_photos.txt')
		local_images=local_images_file_pointer.readlines()
		with table(cls = 't1 t1-localimg'):
			with thead():
				with tr():
					th('Local images Inside target')
			with tbody():
					with tr():
						with td().add(ol()):
							for i in local_images:
								i=i.strip('\n')
								li(p(a(i, href= i)))
		with b(cls='btn'):
			a("Go Back", href='Quick_Scanner_generated_report.html')
		h5("Generated automaticly by Quick Scanner")
	with open("report/Quick_Scanner_local_photos.html", "w") as html_file:
		html_file.write(urldoc.render())
#	pdfkit.from_file('report/Quick_Scanner_local_photos.html', 'report/qs3.pdf')



def create_internet_photos_links():
	urldoc = dominate.document(title="Target URL'S | Quick Scanner")
	with urldoc.head:
		link(rel='preconnect', href='https://fonts.gstatic.com')
		link(href='https://fonts.googleapis.com/css2?family=Do+Hyeon&display=swap', rel='stylesheet')
		link(rel='stylesheet', href='../report_data/style.css')
		link(rel='icon', type='image/x-icon', href="../report_data/favicon.png")
	with urldoc:
		h1("Quick Scanner")
		h2("Scanning report")
		h4("Internet Images",cls='h4-internetimg')
		internet_images_file_pointer=open('report/internet_photos.txt')
		internet_images=internet_images_file_pointer.readlines()
		with table(cls = 't1 t1-internetimg'):
			with thead():
				with tr():
					th('Internet Images Inside target Inside target')
			with tbody():
					with tr():
						with td().add(ol()):
							for i in internet_images:
								i=i.strip('\n')
								li(p(a(i, href= i)))
		with b(cls='btn'):
			a("Go Back", href='Quick_Scanner_generated_report.html')
		h5("Generated automaticly by Quick Scanner")
	with open("report/Quick_Scanner_internet_photos.html", "w") as html_file:
		html_file.write(urldoc.render())
#	pdfkit.from_file('report/Quick_Scanner_internet_photos.html', 'report/qs4.pdf')

def create_main_report():

	high_count=len(sql_list)+len(local_file_inclusion_list)	
	medium_count=len(open_redirection_list)+len(xss_list)
	low_count=len(vulnerable_pages_list)

	vulnerability_count=[]
	vulnerability_count.append(high_count)
	vulnerability_count.append(medium_count)
	vulnerability_count.append(low_count)
	vulnerability_count.append(information_count)

	#print(vulnerability_count)
	doc = dominate.document(title='Quick Scanner')
	with doc.head:
		link(rel='preconnect', href='https://fonts.gstatic.com')
		link(href='https://fonts.googleapis.com/css2?family=Do+Hyeon&display=swap', rel='stylesheet')
		link(rel='icon', type='image/x-icon', href="../report_data/favicon.png")
		link(rel='stylesheet', href='../report_data/style.css')
	with doc:
		h1("Quick Scanner")
		h2("Scanning report")
		h3("Summary of alerts",cls='h3-red')
		with table(id='info', cls='t1 t1-red'):
			with thead():
				with tr():
					for i in vulnerability_table_info:
						th(i)
			with tbody():
				for j in range(0, 4):
					with tr():
						td(vulnerability_levels[j])
						td(vulnerability_count[j])
		br()
		br()
		h3('Vulnerabilities Count',cls='h3-red')
		with table(id='info', cls='t1 t1-red'):
			with thead():
				with tr():
					th('Vulnerability Name')
					th('Count')
			with tbody():
				if(len(sql_list)!=0):
					with tr():
						td('SQL Injection')
						td(len(sql_list))
				if(len(xss_list)!=0):
					with tr():
						td('Cross Site Srcipting')
						td(len(xss_list))
				if(len(local_file_inclusion_list)!=0):
					with tr():
						td('Local File Inclusion')
						td(len(local_file_inclusion_list))
				if(len(open_redirection_list)!=0):
					with tr():
						td('Open Redirection')
						td(len(open_redirection_list))
				if(len(vulnerable_pages_list)!=0):
					with tr():
						td('Default Vulnerable pages')
						td(len(vulnerable_pages_list))
		br()
		br()
		h4('Server Information', cls='h4-yellow')
		h3('Target link : ',server_information.Url)

		with table(cls='t1 t1-extend t1-yellow'):
			with thead():
				with tr():
					th('Description')
					th('Information')
			with tbody():
				if(server_information.Server):
					with tr():
						td("Server Information")
						td(server_information.Server)
				if(server_information.X_Powered_By):
					with tr():
						td("X_Powered_ByPowered_By")
						td(server_information.X_Powered_By)
				if(server_information.Connection):
					with tr():
						td("Connection Type")
						td(server_information.Connection)
				if(server_information.Content_Type):
					with tr():
						td("Content_Type")
						td(server_information.Content_Type)
		h4('More Information', cls='h4-blue')
		with table(cls = 't1 t1-extend t1-blue'):
			with thead():
				with tr():
					th('Description')
					th('Links')
			with tbody():
				with tr():
					td('Target WEB Pages')
					td(a('Quick_Scanner_targeted_url', href='Quick_Scanner_targeted_urls.html'))
				with tr():
					td('Local Photos Inside Target')
					td(a('Quick_Scanner_local_photos', href='Quick_Scanner_local_photos.html'))
				with tr():
					td('Internet Photos Inside Target')
					td(a('Quick_Scanner_internet_photos', href='Quick_Scanner_internet_photos.html'))
				
		h3("Alert Detail")
		#For sql
		for i in range(0, len(sql_list)):
			with table(id='alert', cls='t2 t2-red'):
					with thead():
						with tr():
							for j in sqli_heading:
								th(j)
					with tbody():
						with tr():
							td('Description')
							td((description.sqli))
						with tr():
							td('URL')
							td(sql_list[i]['url'])
						with tr():
							td('Method')
							td(sql_list[i]['method'])
						with tr():
							td('Attack Url')
							td(sql_list[i]['attacked_url'])
						with tr():
							td('Attack Parameters ')
							td(str(sql_list[i]['payload']))
						with tr():
							td('Prevention Methods')
							with td().add(ul()):
								for i in prevention_methods.sqli:
									li(i)
						with tr():
							td('References')
							with td().add(ol()):
								for i in links.sqli_links:
									li(p(a(i, href= i)))
			br()
			br()
		for i in range(0, len(xss_list)):
			with table(id='low', cls='t2 t2-red'):
				with thead():
						with tr():
							for j in xss_heading:
								th(j)
				with tbody():
						with tr():
							td('Description')
							td((description.xss))
						with tr():
							td('URL')
							td(xss_list[i]['url'])
						with tr():
							td('Method')
							td(xss_list[i]['method'])
						with tr():
							td('Form data')
							td(str(xss_list[i]['data']))
						with tr():
							td('Attack Parameters ')
							td(xss_list[i]['payload'])
						with tr():
							td('Prevention Methods')
							with td().add(ul()):
								for i in prevention_methods.xss:
									li(i)
						with tr():
							td('References')
							with td().add(ol()):
								for i in links.xss_links:
									li(p(a(i, href= i)))
			br()
			br()
		if(len(open_redirection_list)>0):
			with table(id='alert', cls='t2 t2-yellow'):
				with thead():
						with tr():
							for j in open_redirection_heading:
								th(j)
				with tbody():
						with tr():
							td('Description')
							td((description.open_redirection))
						with tr():
							td('URL')
							with td().add(ol()):
								for i in open_redirection_list:
									li(i)
						with tr():
							td('Prevention Methods')
							with td().add(ul()):
								for i in prevention_methods.open_redirection:
									li(i)
						with tr():
							td('References')
							with td().add(ol()):
								for i in links.open_redirection:
									li(p(a(i, href= i)))
		br()
		br()
		if(len(local_file_inclusion_list)>0):
			with table(id='alert', cls='t2 t2-yellow'):
				with thead():
						with tr():
							for j in local_file_inclusion_heading:
								th(j)
				with tbody():
						with tr():
							td('Description')
							td((description.lfi))
						with tr():
							td('URL')
							with td().add(ol()):
								for i in local_file_inclusion_list:
									li(i)
						with tr():
							td('Prevention Methods')
							with td().add(ul()):
								for i in prevention_methods.lfi:
									li(i)
						with tr():
							td('References')
							with td().add(ol()):
								for i in links.lfi_links:
									li(p(a(i, href= i)))
		br()
		br()
		if(len(vulnerable_pages_list)>0):
			with table(id='alert', cls='t2 t2-yellow'):
				with thead():
						with tr():
							for j in vulnerable_pages_heading:
								th(j)
				with tbody():
						with tr():
							td('Description')
							td((description.server_misconfiguration))
						with tr():
							td('URL')
							with td().add(ol()):
								for i in vulnerable_pages_list:
									li(i)
						with tr():
							td('Prevention Methods')
							with td().add(ul()):
								for i in prevention_methods.default_pages:
									li(i)
						with tr():
							td('References')
							with td().add(ol()):
								for i in links.default_pages:
									li(p(a(i, href= i)))
		


		h5("Generated automaticly by Quick Scanner")
	with open("report/Quick_Scanner_generated_report.html", "w") as html_file:
		html_file.write(doc.render())
	html_file.close()
	#pdfkit.from_file('report/Quick_Scanner_generated_report.html', 'report/Quick_Scanner_generated_report.pdf')

'''def merge_pdf():
	mergedObject = PdfFileMerger()
	for number in range(1, 5):
		mergedObject.append(PdfFileReader('report/qs'+str(number)+'.pdf', 'rb'))
	mergedObject.write("report/QuickScan-report.pdf")'''
