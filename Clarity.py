from ast import Bytes
import mechanize
from mechanize._mechanize import BrowserStateError
import requests
import time
import threading
import re
import timeit
import chromedriver_autoinstaller


from bs4 import BeautifulSoup
from requests import HTTPError, Response
from tkinter import *
from urllib.error import HTTPError

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.common.exceptions import ElementNotInteractableException
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import JavascriptException
from selenium.common.exceptions import StaleElementReferenceException
from selenium.common.exceptions import InvalidElementStateException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.select import Select

"""
    Pre-Processing
"""
''' code to read payloads from text files - to be implemented later'''

# sql_payloads = [line.strip() for line in open('attacks/sql.txt')]
# xss_payloads = [line.strip() for line in open('attacks/xss.txt')]
# rs_payloads = [line.strip() for line in open('attacks/responsesplitting.txt')]

sql_payloads = ["'",
                "admin' --",
                "admin' #",
                "admin' /*",
                "' or 1=1 #",
                "' or 1=1 /*",
                "') or '1'='1 --",
                "') or ('1'='1 --"]

validation_strings = ["SQL",
                      "error",
                      "stack trace",
                      "logout",
                      "sign out",
                      "database"]

crawling = "Crawling web pages...\n"
progression = "Current page...\n"

chrome_driver_path = "drivers\chromedriver.exe"

# creates browser object, set handles and user agent
br = mechanize.Browser()
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.addheaders = \
    [('User-agent',
      'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

# set chrome options for selenium
chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument("--log-level=3")


def crawler(start_url):
    """
        Function to get all links from a given web page.
    """
    # if "one page only" is selected, check the provided URL exists and display it
    if r.get() == 2:
        try:
            response = requests.get(start_url)  # create request
            BeautifulSoup(response.text, 'html5lib')  # create bs4 object
            print_crawler(crawling + '\n' + start_url)
        except:
            print_err_message()

    else:
        urls = set()

        try:
            response = requests.get(start_url)  # create request
            soup = BeautifulSoup(response.text, 'html5lib')  # create bs4 object
            tags = soup.find_all('a')  # find all links on the page

            urls.add(start_url)  # add start_url to urls set

            # for each link...
            for tag in tags:
                try:
                    # ignore social media links and email addresses
                    if "twitter" in tag.get('href') \
                            or "facebook" in tag.get('href') \
                            or "instagram" in tag.get('href') \
                            or "myspace" in tag.get('href') \
                            or "mailto" in tag.get('href'):
                        continue
                    # if tag contains entire website, add tag to set
                    elif "http" in str(tag.get('href')):
                        urls.add(tag.get('href'))
                    # else add start url + tag
                    else:
                        tag = str(tag.get('href'))
                        urls.add(start_url + tag)  # add start_url + anchor to set
                except:
                    continue

            print_crawler(crawling)  # print to text area
            text_crawler.configure(state='normal')  # set text area as editable

        except Exception:
            print_err_message()

        # display crawled urls in text area
        for anchor in urls:
            progress = f"\n{anchor}"
            text_crawler.insert(INSERT, progress)

        text_crawler.config(state='disabled')  # set the text area as un-editable after it has been written to

        return urls  # returns set of url subdirectories


def sql(url, vul_count, pages):
    """
        Test for SQL injection vulnerabilities
    """

    # "Scan one page"
    if r.get() == 2:
        try:
            br.open(url)
            print_progress(progression, "\n" + url)

            """
                Fuzzing Phase
            """
            for form in br.forms():
                if is_login_form(form):
                    for payload in sql_payloads:
                        br.form = list(br.forms())[0]

                        for control in br.form.controls:
                            if control.type == "text":
                                try:
                                    control._value = payload
                                except IndexError:
                                    break
                        try:
                            br.submit()  # submit form
                        except HTTPError:
                            continue

                        """
                            Validation Phase
                        """
                        time.sleep(1)   # CAN PROB GET RID OF THIS
                        updated_url = br.geturl()  # get current url
                        response = br.open(updated_url)  # open current url
                        time.sleep(1)

                        data = response.read()
                        soup = BeautifulSoup(data, 'html5lib')

                        # if the new page contains any of the validation strings, likely found a vulnerability.
                        for v in validation_strings:
                            if soup.findAll(text=re.compile(v)):
                                print_results(f"SQL Injection Vulnerability Detected: \n {url} \n")
                                vul_count += 1
                                break
        except:
            print_err_message()

    # "Scan all pages"
    else:
        # loops through all pages in given URL
        for page in pages:
            print_progress(progression, page)
            try:
                br.open(page)  # opens the url
            except Exception:
                continue

            """
                Fuzzing Phase -- ONLY TESTS FIRST PAYLOAD
            """
            for form in br.forms():
                if is_login_form(form):
                    for payload in sql_payloads:
                        br.form = list(br.forms())[0]

                        for control in br.form.controls:
                            if control.type == "text":
                                try:
                                    control._value = payload
                                except IndexError:
                                    break
                        try:
                            br.submit()  # submit form
                        except HTTPError:
                            continue

                        """
                            Validation Phase
                        """
                        time.sleep(1)   # CAN PROB GET RID OF THIS
                        updated_url = br.geturl()  # get current url
                        response = br.open(updated_url)  # open current url
                        time.sleep(1)

                        data = response.read()
                        soup = BeautifulSoup(data, 'html5lib')

                        for v in validation_strings:
                            if soup.findAll(text=re.compile(v)):
                                print_results(f"SQL Injection Vulnerability Detected: \n {page} \n")
                                vul_count += 1
                                break

    num_vul = f"Num. of SQLi vulnerabilities found: {vul_count}\n\n"
    print_results(num_vul)  # print number of vulnerabilities detected

    print_progress("Scan Complete!")


def session(url, vul_count, pages):
    """
        Test for session management vulnerabilities
    """
    http_count = 0
    secure_count = 0

    # "Scan one page"
    if r.get() == 2:
        print_progress(progression, f"\n{url}")
        try:
            req = requests.post(url)
        except:
            pass

        for cookie in req.cookies:
            a = cookie.__dict__.get('_rest')
            if a:
                # if httponly cookie is not set, we have a possible vulnerability
                if "'httponly': none" in str(a).lower():
                    vul_count += 1
                    http_count += 1

                # if secure cookie is not set, we have a possible vulnerability
                if not cookie.secure:
                    vul_count += 1
                    secure_count += 1

    # "Scan all pages"
    else:
        for page in pages:
            print_progress(progression, page)
            try:
                req = requests.post(page)
            except:
                continue

            for cookie in req.cookies:
                a = cookie.__dict__.get('_rest')
                if a:
                    # if httponly cookie is not set, we have a possible vulnerability
                    if "'httponly': none" in str(a).lower():
                        vul_count += 1
                        http_count += 1

                    # if secure cookie is not set, we have a possible vulnerability
                    if not cookie.secure:
                        vul_count += 1
                        secure_count += 1

    if secure_count > 0:
        print_results(f"Session Vulnerability Detected: \n session cookie without secure flag: {secure_count}\n")
    if http_count > 0:
        print_results(f"Session Vulnerability Detected: \n session cookie without HttpOnly flag: {http_count}\n")

    num_vul = f"\nNum. of Session vulnerabilities found: {vul_count}\n\n"
    print_results(num_vul)  # print number of vulnerabilities detected

    print_progress("Scan Complete!")


def xss(url, vul_count, pages):
    """
        Test for XSS injection vulnerabilities
    """
    chromedriver_autoinstaller.install()  # Check if the current version of chromedriver exists
                                      # and if it doesn't exist, download it automatically,
                                      # then add chromedriver to path

    driver = webdriver.Chrome()
    driver = webdriver.Chrome(options=chrome_options)

    email_flag = False
    entry_flag = False

    alert_text = ""
    found_string = f"XSS Vulnerability Detected: \n {url} \n"

    # "Scan one page"
    if r.get() == 2:
        print_progress(progression, "\n" + url)

        try:
            driver.get(url)  # opens page
            time.sleep(1)
        except Exception:
            print_err_message()

        """
            Fuzzing Phase
        """
        try:
            # find DEPs on page
            form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')
            entries = driver.find_elements(By.XPATH, "//input[@type='text']")
            passwords = driver.find_elements(By.XPATH, "//input[@type='password']")
            emails = driver.find_elements(By.XPATH, "//input[@type='email']")

            # if DEPs are found, perform fuzzing - if not, continue to next page
            if form_field:
                for email in emails:
                    email.send_keys("test812.346test@gmail.com")  # random email string unlikely to already exist
                    email_flag = True
                for entry in entries:
                    entry.send_keys("<ScRiPt>alert('XSS Vulnerable')</ScRiPt>")  # attack string
                    entry_flag = True
                for pwd in passwords:
                    pwd.send_keys("a3M$c2N£b1B%")  # password string to match any possible requirements

                if entry_flag:
                    entry.submit()  # submit form
                elif email_flag:
                    email.submit()

        except (NoSuchElementException, ElementNotInteractableException,
                JavascriptException, StaleElementReferenceException,
                InvalidElementStateException):
            pass

        """
            Validation Phase
        """
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
            alert = driver.switch_to.alert  # switch to alert popup
            alert_text = alert.text  # get text of popup
        except TimeoutException:
            pass

        # read popup and check for attack string, if present, page is vulnerable
        if "XSS Vulnerable" in alert_text:
            print_results(found_string)
            vul_count += 1

        driver.quit()  # close the browser

    # "Scan all pages"
    else:
        # for all pages in web application
        for page in pages:
            found_string = f"XSS Vulnerability Detected: \n {page} \n"
            print_progress(progression, page)
            try:
                driver.get(page)  # open page
                time.sleep(1)
            except Exception:
                continue

            """
                Fuzzing Phase
            """
            try:
                # find DEPs on page
                form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')
                entries = driver.find_elements(By.XPATH, "//input[@type='text']")
                passwords = driver.find_elements(By.XPATH, "//input[@type='password']")
                emails = driver.find_elements(By.XPATH, "//input[@type='email']")

                # if DEPs are found, perform fuzzing - if not, continue to next page
                if form_field:
                    for email in emails:
                        email.send_keys("test812.346test@gmail.com")
                    for entry in entries:
                        entry.send_keys("<ScRiPt>alert('XSS Vulnerable')</ScRiPt>")
                    for pwd in passwords:
                        pwd.send_keys("a3M$c2N£b1B%")  # password string to match any possible requirements

                    if entry_flag:
                        entry.submit()  # submit form
                    elif email_flag:
                        email.submit()

            except (NoSuchElementException, ElementNotInteractableException,
                    JavascriptException, StaleElementReferenceException,
                    InvalidElementStateException):
                continue

            """
                Validation Phase
            """
            try:
                WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
                alert = driver.switch_to.alert  # switch to alert popup
                alert_text = alert.text  # get text of popup

                # check if the attack string is in the popup, if it is, page is vulnerable
                if "XSS Vulnerable" in alert_text:
                    print_results(found_string)
                    vul_count += 1
            except TimeoutException:
                continue

    driver.quit()

    num_vul = f"Num. of XSS vulnerabilities found: {vul_count}\n\n"
    print_results(num_vul)  # print number of vulnerabilities detected

    print_progress("Scan Complete!")


def splitting(url, vul_count, pages):


    chromedriver_autoinstaller.install()  # Check if the current version of chromedriver exists
                                      # and if it doesn't exist, download it automatically,
                                      # then add chromedriver to path

    driver = webdriver.Chrome()
    driver = webdriver.Chrome(options=chrome_options)

    email_flag = False
    entry_flag = False
    alert_text = ""

    found_string = f"HTTP Splitting Vulnerability Detected: \n {url} \n"

    if r.get() == 2:
        print_progress(progression, "\n" + url)

        try:
            driver.get(url)  # opens page
        except:
            print_err_message()
            time.sleep(1)

        """
            Fuzzing Phase
        """
        try:
            # find DEPs on page
            form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')


            # if DEPs are found, perform fuzzing - if not, continue to next page
            if form_field:
                for entry in entries:
                    entry.send_keys(
                        "Test%0d%0a%0d%0a<ScRiPt>alert('HTTP Splitting Vulnerable')</ScRiPt>")  # attack string
                    entry_flag = True
                for pwd in passwords:
                    pwd.send_keys("a3M$c2N£b1B%")  # password string to match any possible requirements
                for email in emails:
                    email.send_keys("test812.346test@gmail.com")  # random email string unlikely to already exist
                    email_flag = True

                if entry_flag:
                    entry.submit()  # submit form
                elif email_flag:
                    email.submit()
        except (NoSuchElementException, ElementNotInteractableException, JavascriptException):
            pass

        """
            Validation Phase
        """
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
            alert = driver.switch_to.alert  # switch to alert popup
            alert_text = alert.text  # get text of popup

        except TimeoutException:
            driver.quit()

        # read popup and check for attack string, if present, page is vulnerable
        if "HTTP Splitting Vulnerable" in alert_text:
            print_results(found_string)
            vul_count += 1

        driver.quit()  # close the browser

    else:
        # for all pages in web application
        for page in pages:
            found_string = f"HTTP Splitting Vulnerability Detected: \n {page} \n"
            print_progress(progression, page)
            try:
                driver.get(page)  # open page
                time.sleep(1)
            except Exception:
                continue

            """
                Fuzzing Phase
            """
            try:
                # find DEPs on page
                form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')
                entries = driver.find_elements(By.XPATH, "//input[@type='text']")
                passwords = driver.find_elements(By.XPATH, "//input[@type='password']")
                emails = driver.find_elements(By.XPATH, "//input[@type='email']")

                # if DEPs are found, perform fuzzing - if not, continue to next page
                if form_field:
                    for entry in entries:
                        entry.send_keys(
                                "Test%0d%0a%0d%0a<ScRiPt>alert('HTTP Splitting Vulnerable')</ScRiPt>")  # attack string
                    for pwd in passwords:
                        pwd.send_keys("a3M$c2N£b1B%")  # password string to match any possible requirements
                    for email in emails:
                        email.send_keys("test812.346test@gmail.com")  # random email string unlikely to already exist

                    if entry_flag:
                        entry.submit()  # submit form
                    elif email_flag:
                        email.submit()

            except (NoSuchElementException, ElementNotInteractableException, JavascriptException):
                continue

            """
                Validation Phase
            """
            try:
                WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
                alert = driver.switch_to.alert  # switch to alert popup
                alert_text = alert.text  # get text of popup

                # check if the attack string is in the popup, if it is, page is vulnerable
                if "HTTP Splitting Vulnerable" in alert_text:
                    print_results(found_string)
                    vul_count += 1
            except TimeoutException:
                continue

    driver.quit()

    num_vul = f"Num. of HTTP Splitting vulnerabilities found: {vul_count}\n\n"
    print_results(num_vul)  # print number of vulnerabilities detected

    print_progress("Scan Complete!")


def full_scan(url, pages):
    start = timeit.default_timer()
    chromedriver_autoinstaller.install()  # Check if the current version of chromedriver exists
                                      # and if it doesn't exist, download it automatically,
                                      # then add chromedriver to path

    driver = webdriver.Chrome()
    driver = webdriver.Chrome(options=chrome_options)


    email_flag = False
    entry_flag = False

    sql_count = 0
    xss_count = 0
    splitting_count = 0

    secure_count = 0
    http_count = 0

    alert_text = ""
    xss_found_string = f"XSS Vulnerability Detected: \n {url} \n"
    splitting_found_string = f"HTTP Splitting Vulnerability Detected: \n {url} \n"
    sql_found_string = f"SQL Injection Vulnerability Detected: \n {url} \n"

    # "Scan one page"
    if r.get() == 2:
        print_progress(progression, "\n" + url)

        try:
            driver.get(url)  # opens page
            time.sleep(1)
        except:
            print_err_message()

        # find DEPs on page
        form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')
        entries = driver.find_elements(By.XPATH, "//input[@type='text']")
        passwords = driver.find_elements(By.XPATH, "//input[@type='password']")
        emails = driver.find_elements(By.XPATH, "//input[@type='email']")

        """
            XSS --- Fuzzing Phase
        """
        try:
            # if DEPs are found, perform fuzzing - if not, continue to next page
            if form_field:
                for email in emails:
                    email.send_keys("test812.346test@gmail.com")  # random email string unlikely to already exist
                    email_flag = True
                for entry in entries:
                    entry.send_keys("<ScRiPt>alert('XSS Vulnerable')</ScRiPt>")  # attack string
                    entry_flag = True
                for pwd in passwords:
                    pwd.send_keys("a3M$c2N£b1B%")  # password string to match any possible requirements

                if entry_flag:
                    entry.submit()  # submit form
                elif email_flag:
                    email.submit()
        except (NoSuchElementException, ElementNotInteractableException,
                JavascriptException, StaleElementReferenceException,
                InvalidElementStateException):
            pass

        """
            XSS --- Validation Phase
        """
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
            alert = driver.switch_to.alert  # switch to alert popup
            alert_text = alert.text  # get text of popup

        except TimeoutException:
            pass

        # read popup and check for attack string, if present, page is vulnerable
        if "XSS Vulnerable" in alert_text:
            print_results(xss_found_string)
            xss_count += 1
            alert_text = ""  # clear alert_text

        """
            HTTP Response Splitting --- Fuzzing Phase
        """
        form_field = driver.find_elements_by_xpath("//input[@type='text' or @type='email' or @type='password']")
        try:
            # ".clear()" clears the form field ready to be fuzzed with new contents
            if form_field:
                for field in form_field:
                    field.clear()
                    field.send_keys("Test%0d%0a%0d%0a<ScRiPt>alert('HTTP Splitting Vulnerable')</ScRiPt>")
                field.submit()
        except (NoSuchElementException, ElementNotInteractableException,
                JavascriptException, StaleElementReferenceException,
                InvalidElementStateException):
            pass

        """
            HTTP Response Splitting --- Validation Phase
        """
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text

        except TimeoutException:
            pass

        if "HTTP Splitting Vulnerable" in alert_text:
            print_results(splitting_found_string)
            splitting_count += 1
            alert_text = ""

        """
            SQL Injection --- Fuzzing Phase
        """
        try:
            br.open(url)
        except:
            print_err_message()

        for form in br.forms():  # loops through all forms on the page
            if is_login_form(form):  # checks if form is a login form
                for payload in sql_payloads:  # loops through all possible attack strings
                    br.form = list(br.forms())[0]  # selects form

                    for control in br.form.controls:  # for each control in form
                        if control.type == "text":  # if control type is "text"
                            try:
                                control._value = payload  # form fields set to SQLi attack string
                            # end loop when we reach last field
                            except IndexError:
                                break
                    try:
                        br.submit()  # submit form
                    except HTTPError:
                        continue

                    """
                        SQL Injection --- Validation Phase
                    """
                    # sleep for 1 second after submitting form to give new page time to load
                    time.sleep(1)
                    updated_url = br.geturl()  # get current url
                    response = br.open(updated_url)  # open current url
                    time.sleep(1)

                    data = response.read()
                    soup = BeautifulSoup(data, 'html5lib')

                    # if the new page contains any of the validation strings, likely found a vulnerability.
                    for v in validation_strings:
                        if soup.findAll(text=re.compile(v)):
                            print_results(sql_found_string)
                            sql_count += 1
                            break

        """
            Session Management Flaws
        """
        try:
            req = requests.post(url)
        except:
            pass

        for cookie in req.cookies:
            a = cookie.__dict__.get('_rest')
            if a:
                # if httponly cookie is not set, we have a possible vulnerability
                if "'httponly': none" in str(a).lower():
                    http_count += 1

                # if secure cookie is not set, we have a possible vulnerability
                if not cookie.secure:
                    secure_count += 1

    # scan all pages
    else:
        for page in pages:

            xss_found_string = f"XSS Vulnerability Detected: \n {page} \n"
            splitting_found_string = f"HTTP Splitting Vulnerability Detected: \n {page} \n"
            sql_found_string = f"SQL Injection Vulnerability Detected: \n {page} \n"

            print_progress(progression, "\n" + page)
            try:
                driver.get(page)  # opens page
            except:
                continue

            # find DEPs on page
            form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')
            entries = driver.find_elements(By.XPATH, "//input[@type='text']")
            passwords = driver.find_elements(By.XPATH, "//input[@type='password']")
            emails = driver.find_elements(By.XPATH, "//input[@type='email']")

            """
                XSS --- Fuzzing Phase
            """
            try:
                # if DEPs are found, perform fuzzing - if not, continue to next page
                if form_field:
                    for email in emails:
                        email.send_keys("test812.346test@gmail.com")  # random email string unlikely to already exist
                        email_flag = True
                    for entry in entries:
                        entry.send_keys("<ScRiPt>alert('XSS Vulnerable')</ScRiPt>")  # attack string
                        entry_flag = True
                    for pwd in passwords:
                        pwd.send_keys("a3M$c2N£b1B%")  # password string to match any possible requirements

                    if entry_flag:
                        entry.submit()  # submit form
                    elif email_flag:
                        email.submit()
            except (NoSuchElementException, ElementNotInteractableException,
                    JavascriptException, StaleElementReferenceException,
                    InvalidElementStateException):
                pass

            """
                XSS --- Validation Phase
            """
            try:
                WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
                alert = driver.switch_to.alert  # switch to alert popup
                alert_text = alert.text  # get text of popup

            except TimeoutException:
                pass

            # read popup and check for attack string, if present, page is vulnerable
            if "XSS Vulnerable" in alert_text:
                print_results(xss_found_string)
                xss_count += 1
                alert_text = ""  # clear alert_text

            """
                HTTP Response Splitting --- Fuzzing Phase
            """
            form_field = driver.find_elements(By.XPATH,'//input[@type="text" or @type="email" or @type="password"]')


            try:
                if form_field:
                    # ".clear()" clears the form field ready to be fuzzed with new contents
                    for field in form_field:
                        field.clear()
                        field.send_keys("Test%0d%0a%0d%0a<ScRiPt>alert('HTTP Splitting Vulnerable')</ScRiPt>")
                    field.submit()
            except (NoSuchElementException, ElementNotInteractableException,
                    JavascriptException, StaleElementReferenceException,
                    InvalidElementStateException):
                pass

            """
                HTTP Response Splitting --- Validation Phase
            """
            try:
                WebDriverWait(driver, 1).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert_text = alert.text

            except TimeoutException:
                pass

            if "HTTP Splitting Vulnerable" in alert_text:
                print_results(splitting_found_string)
                splitting_count += 1
                alert_text = ""

            """
                SQL Injection --- Fuzzing Phase
            """
            try:
                br.open(page)
            except:
                continue

            try:
                for form in br.forms():  # loops through all forms on the page
                    if is_login_form(form):  # checks if form is a login form
                        for a in sql_payloads:  # loops through all possible attack strings
                            try:
                                br.form = list(br.forms())[0]  # selects form
                            except IndexError:
                                continue

                            for control in br.form.controls:  # for each control in form
                                if control.type == "text":  # if control type is "text"
                                    try:
                                        control._value = a  # form fields set to SQLi attack string
                                    # end loop when we reach last field
                                    except IndexError:
                                        break
                            try:
                                br.submit()  # submit form
                            except HTTPError:
                                pass

                            """
                                SQL Injection --- Validation Phase
                            """
                            # sleep for 1 second after submitting form to give new page time to load
                            time.sleep(1)
                            updated_url = br.geturl()  # get current url
                            response = br.open(updated_url)  # open current url
                            time.sleep(1)

                            data = response.read()
                            soup = BeautifulSoup(data, 'html5lib')

                            # if the new page contains any of the validation strings, likely found a vulnerability.
                            for v in validation_strings:
                                if soup.find_all(string=re.compile(v)):
                                    print_results(sql_found_string)
                                    sql_count += 1
                                    break
                                break
            except BrowserStateError:
                continue


            """
                Session Management Flaws
            """
            try:
                req = requests.post(page)
            except:
                continue

            for cookie in req.cookies:
                a = cookie.__dict__.get('_rest')
                if a:
                    # if httponly cookie is not set, we have a possible vulnerability
                    if "'httponly': none" in str(a).lower():
                        http_count += 1

                    # if secure cookie is not set, we have a possible vulnerability
                    if not cookie.secure:
                        secure_count += 1

    driver.quit()
    session_count = secure_count + http_count

    if secure_count > 0:
        print_results(f"Session Vulnerability Detected: \n session cookie without secure flag: {secure_count}\n")
    if http_count > 0:
        print_results(f"Session Vulnerability Detected: \n session cookie without HttpOnly flag: {http_count}\n")
    num_vul = f"\nNum. of Session vulnerabilities found: {session_count}\n"
    print_results(num_vul)
    num_vul = f"\nNum. of SQLi vulnerabilities found: {sql_count}\n"
    print_results(num_vul)
    num_vul = f"\nNum. of XSS vulnerabilities found: {xss_count}\n"
    print_results(num_vul)
    num_vul = f"\nNum. of HTTP Splitting vulnerabilities found: {splitting_count}\n"
    print_results(num_vul)

    print_progress("Scan Complete!")

    end = timeit.default_timer() - start  # end time
    print("\n\n\n", end)


def getValue():
    """
    Looks at what value is in OptionMenu (option)
    Depends what the scan does depending on the option selected
    """

    # run full scan against target
    if option.get() == "Full Scan":
        clear_text_areas()  # clear before running

        t1 = threading.Thread(target=full_scan, args=(entry_target.get(), crawler(entry_target.get()),))
        t1.start()

    # only crawl target web application
    elif option.get() == "Crawl Only":
        clear_text_areas()  # clear before running

        t2 = threading.Thread(target=crawler, args=(entry_target.get(),))
        t2.start()

    # run SQL Injection scan against target
    elif option.get() == "SQL Injection":
        clear_text_areas()  # clear before running
        vul_count = 0

        if "dvwa" in entry_target.get():
            t3 = threading.Thread(target=dvwa_test_case_sqli, args=(entry_target.get(), vul_count,))
            t3.start()
        else:
            t4 = threading.Thread(target=sql, args=(entry_target.get(), vul_count, crawler(entry_target.get()),))
            t4.start()

    # run XSS scan against target
    elif option.get() == "Cross-Site Scripting":
        clear_text_areas()  # clear before running
        vul_count = 0

        # bwapp for testing purposes
        if "bwapp" in entry_target.get():
            t5 = threading.Thread(target=bwapp_test_case_xss, args=(entry_target.get(), vul_count))
            t5.start()
        else:
            t6 = threading.Thread(target=xss, args=(entry_target.get(), vul_count, crawler(entry_target.get()),))
            t6.start()

    # run Session Management vulnerability scan against target
    elif option.get() == "Session Management Flaws":
        clear_text_areas()  # clear before running
        vul_count = 0
        http_count = 0
        secure_count = 0

        t7 = threading.Thread(target=session, args=(entry_target.get(), vul_count, crawler(entry_target.get()),))
        t7.start()

    # run HTTP Response Splitting vulnerability scan against target
    elif option.get() == "HTTP Response Splitting":
        clear_text_areas()  # clear before running
        vul_count = 0

        t8 = threading.Thread(target=splitting, args=(entry_target.get(), vul_count, crawler(entry_target.get()),))
        t8.start()


def bwapp_test_case_xss(url, vul_count):
    """
    For Testing purposes ONLY (remove for final product)
    """
    if r.get() == 2:
        print_crawler(crawling + '\n' + url)
        print_progress(progression, "\n" + url)

        chrome_options = Options()
        chrome_options.add_argument("user-data-dir=selenium")
        driver = webdriver.Chrome(options=chrome_options)

        driver.get(url)
        """
            LOGIN TO BWAPP
        """
        try:
            username = driver.find_element_by_id("login")
            password = driver.find_element_by_id("password")

            username.send_keys("bee")
            password.send_keys("bug")

            driver.find_element_by_name("form").click()
        except:
            print("")

        time.sleep(1)
        driver.get(url)
        # time.sleep(1)

        """
            Fuzzing Phase
        """
        # find DEPs
        entries = driver.find_elements_by_xpath("//input[@type='text' or @type='password']")

        # fill each DEP with attack string
        for entry in entries:
            entry.send_keys("<ScRiPt>alert('XSS Vulnerable')</ScRiPt>")

        # hit enter, submitting the form
        try:
            entries[0].send_keys(Keys.ENTER)
        except IndexError:
            print("")

        """
            Validation Phase
        """
        found_string = f"XSS Vulnerability Detected: \n {url} \n"
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present())  # check if alert is present, wait 1 seconds
            alert = driver.switch_to.alert  # switch to alert popup
            alert_text = alert.text  # get text of popup
        except TimeoutException:
            noVuls()
            driver.quit()

        # check if the attack string is in the popup, if it is, page is vulnerable
        if "XSS Vulnerable" in alert_text:
            print_results(found_string)
            vul_count += 1

        driver.quit()

        num_vul = f"\nNum. of XSS vulnerabilities found: {vul_count}"
        print_results(num_vul)  # print number of vulnerabilities detected

    else:
        print_progress("Single Page Only")

    print_progress("Scan Complete!")


def dvwa_test_case_sqli(url, vul_count):
    """
    For Testing purposes ONLY (remove for final product)
    """
    sql_payloads = ["'",
                    "admin' --",
                    "admin' #",
                    "admin' /*",
                    "' or 1=1 #",
                    "' or 1=1 /*",
                    "') or '1'='1 --",
                    "') or ('1'='1 --"]

    validation_strings = ["SQL",
                          "error",
                          "stack trace",
                          "logout",
                          "sign out",
                          "database"]

    print_progress(progression, f"\n {url}")

    if r.get() == 2:
        """
            LOGIN TO DVWA
        """
        br = mechanize.Browser()
        br.set_handle_equiv(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)

        # set user-agent
        br.addheaders = \
            [('User-agent',
              'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

        br.open(url)
        br.select_form(nr=0)
        br.form["username"] = "admin"
        br.form["password"] = "password"
        br.submit()

        """
            SET DIFFICULTY
        """
        br.open("http://localhost/dvwa/security.php")
        for form in br.forms():
            br.form = list(br.forms())[0]
            form["security"] = ["low"]
            br.submit()

        time.sleep(1)
        br.open(url)

        """
            Fuzzing Phase
        """
        for form in br.forms():  # loops through all forms on the page
            for a in sql_payloads:  # loops through all possible attack strings
                count = 0  # resets count for each form
                br.form = list(br.forms())[0]  # selects form

                # for each control in form
                for control in br.form.controls:
                    # if control type is "text"
                    if control.type == "text":
                        try:
                            control._value = a  # form fields set to SQLi attack string
                            print(form.controls[count])
                            count += 1

                        # end loop when we reach last field
                        except IndexError:
                            break
                try:
                    br.submit()  # submit form
                except HTTPError:
                    continue

                """
                    Validation Phase
                """
                # sleep for 1 second after submitting form to give new page time to load
                time.sleep(1)
                updated_url = br.geturl()  # get current url
                response = br.open(updated_url)  # open current url
                time.sleep(1)

                data = response.read()
                soup = BeautifulSoup(data, 'html5lib')

                # string to display if a vulnerability is detected and on what page
                found_string = f"SQL Injection Vulnerability Detected: \n {url} \n"

                # if the new page contains any of the validation strings, likely found a vulnerability.
                for v in validation_strings:
                    if soup.findAll(text=re.compile(v)):
                        print_results(found_string)
                        vul_count += 1
                        break
                break

        if vul_count == 0:
            noVuls()
        else:
            num_vul = f"Num. of SQLi vulnerabilities found: {vul_count}"
            print_results(num_vul)  # print number of vulnerabilities detected

    else:
        print_progress("Single Page Only")


def print_err_message():
    """
    Displays Error Message in Text Area
    """
    err = "[-] Something went wrong!"
    text_progress.configure(state='normal')
    text_progress.delete(1.0, END)
    text_progress.insert(INSERT, err)
    text_progress.configure(state='disabled')


def print_progress(*args):
    """
    Writes To text_progress Text Area
    """
    text_progress.configure(state='normal')
    text_progress.delete(1.0, END)
    for a in args:
        text_progress.insert(INSERT, a)
    text_progress.configure(state='disabled')


def print_crawler(*args):
    """
    Writes To text_progress Text Area
    """
    text_crawler.configure(state='normal')
    text_crawler.delete(1.0, END)
    for a in args:
        text_crawler.insert(INSERT, a)
    text_crawler.configure(state='disabled')


def print_results(*args):
    """
    Writes To text_results Text Area
    """
    text_results.configure(state='normal')
    for a in args:
        text_results.insert(INSERT, a)
    text_results.configure(state='disabled')


def clear_text_areas():
    # clear progress text area
    text_progress.configure(state='normal')
    text_progress.delete(1.0, END)
    text_progress.configure(state='disabled')

    # clear crawling text box
    text_crawler.configure(state='normal')
    text_crawler.delete(1.0, END)
    text_crawler.configure(state='disabled')

    # clear results text box
    text_results.configure(state='normal')
    text_results.delete(1.0, END)
    text_results.configure(state='disabled')


def is_login_form(form):
    # for for in forms, if the form contains a common name for a login form, return True
    if str(form.name).lower() == "login":
        return True
    elif str(form.name).lower() == "loginform":
        return True
    elif str(form.name).lower() == "login_form":
        return True
    elif str(form.name).lower() == "customerlogin":
        return True
    elif str(form.name).lower() == "customer_login":
        return True
    elif str(form.name).lower() == "signin":
        return True
    elif str(form.name).lower() == "sign_in":
        return True
    elif str(form.name).lower() == "sign_in_form":
        return True

    # if the form has an password field (commonly used for logging in) return true
    for control in form.controls:
        if control.type == "password":
            return True

    # else return False
    return False


'''
    GRAPHICAL USER INTERFACE
'''
root = Tk()  # creates window

# set window size, title, and background colour, and sets it to non-resizable
root.geometry("900x620")
root.title("Clarity")
root.configure(background='#F2F2F2')
root.resizable(False, False)

# fill space with blank widgets to create a cleaner layout
for i in range(10):
    Frame(root, width=20, height=20, background='#F2F2F2').grid(row=0, column=i)

for j in range(10):
    Frame(root, width=20, height=20, background='#F2F2F2').grid(row=j, column=0)

# options for menu
options = [
    "Full Scan",
    "Crawl Only",
    "SQL Injection",
    "Cross-Site Scripting",
    "Session Management Flaws",
    "HTTP Response Splitting"
]
option = StringVar()
option.set(options[0])

# create menu
drop = OptionMenu(root, option, *options)

# create labels
label_target = Label(root, text="Target Web Application:")

# create entries
entry_target = Entry(root, width=40)

# create text areas
text_progress = Text(root, width=50, height=3, wrap=NONE)
text_crawler = Text(root, width=50, height=15, wrap=NONE)
text_results = Text(root, width=40, wrap=NONE)

# create buttons
button_start = Button(root, text="Start Scan", width=10, height=2, bg='#08F26E', command=getValue)

# create radio buttons
r = IntVar()
r.set("1")
radio_one = Radiobutton(root, text="Scan all pages", variable=r, value=1)
radio_two = Radiobutton(root, text="Scan one page", variable=r, value=2)

# place objects
label_target.grid(row=2, column=2)
entry_target.grid(row=2, column=3, sticky=W)
text_progress.grid(columnspan=2, row=4, column=2, sticky=SE)
text_crawler.grid(columnspan=2, row=4, column=2, sticky=NE)
text_results.grid(columnspan=2, row=4, column=6)
drop.grid(row=2, column=7)
radio_one.grid(row=3, column=7, sticky=W)
radio_two.grid(row=3, column=7, sticky=E)
drop.config(width=30)
button_start.grid(row=6, column=2)

# style objects
label_target.configure(font=("Helvetica", 10, "bold"))
drop.configure(font=("Helvetica", 10, "bold"))
button_start.configure(font=("Helvetica", 10, "bold"))
text_progress.configure(state='disabled', font=("Helvetica", 10))
text_crawler.configure(state='disabled', font=("Helvetica", 10))
text_results.configure(state='disabled', font=("Helvetica", 10))
entry_target.insert(INSERT, "http://")

root.mainloop()  # keep window open