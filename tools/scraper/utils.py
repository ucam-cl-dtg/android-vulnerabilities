# Copyright (C) Sergio Pastrana 2018
# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
import time
import sqlite3
import os
import signal


# Timeout for http an request (in seconds)
HTTP_TIMEOUT=60

# Maximum HTTP request to perform before considering the page is not found
MAX_ATTEMPTS=4

# Name of the database
DB_NAME='data.db'
		
def alarmHandler (signum,frame):
	raise Exception('Timeout')

def fetchPage(driver,url):
	"""
	Fetchs the page of the url using the given driver
	"""
	driver.get('about:blank');
	try:
		driver.get(url)
	except Exception as e:
		print(('Could not fetch page. %s:%s)'%(e.__class__.__name__,e)))
	try:
		title=driver.execute_script("return arguments[0].text",driver.find_element_by_xpath('//title'))
		if "404 Not Found" in title:
			raise Exception
	except:
		return False;
	return True

def quitDriver(driver):
	driver.service.process.send_signal(signal.SIGTERM)
	try:
		driver.quit()
	except:
		pass;
def getDriver():
	""""" 
	Returns a webdriver instance for the Firefox client
	"""""

	t=0
	maxTries=4
	while (t<maxTries):
		try:
			driver = webdriver.Firefox()
			break;
		except Exception as e:
			t+=1
			print(("Could not create the firefox driver (trying %s/%s): %s"%(t,maxTries,e)))
			time.sleep(5);
	if (t==maxTries):
		print ("FATAL. Could not create the firefox driver")
		exit()	
	return driver
