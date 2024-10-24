# A test script for CSC2330 Assignment 3

# test.py connects to an instance of the app_improved.py server, and performs some 
# limited testing of whether a user can log in, request aphorisms and log out, 
# while seeing the expected outputs.

# There are two requirements to be installed with pip:
# flask
# bs4

# Items tested include:
# Accessing the /login page
# Logging in 
# Accessing the /restricted page
# Requesting an aphorism from /restricted
# Logging out

# Usage:
# There are five arguments
# --url 
#   A URL for the running instance of app_improved.py, includes the port. 
#   Default is http://127.0.0.1:5000
# --username
#   The username for the application, e.g. u1234567
# --password
#   The user's password
# -h
#   Will display usage information

#   e.g 
#   python3 ./test.py --url http://127.0.0.1:5000 --username u1234567 --password csc2330a3

import argparse
from bs4 import BeautifulSoup
import http.cookiejar
import ssl
import urllib.parse
import urllib.request

# The address and port that app_improved.py is listening on.
# Supplied by command line arguments.
server = None

# For storing a logged in session cookie
session_cookie = ''

# For storing an SSL context
ctx = None

# ----- Helper functions ----- 
# Function to extract CSRF token from HTML
def extract_csrf_token_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrf_token'})

    if csrf_input:
        return csrf_input['value']
    
    return None

# Function to retrieve a cookie from the jar
def extract_cookie_from_cookie_jar(cookie_jar, name):
    for cookie in cookie_jar:
        if cookie.name == name:

            return cookie.value
        
    return None

def can_access_login_form() :
# Performs a get request for /login and expects the page title to be 
# 'Please log in'
    url = server + '/login'

    # Create a request object
    request = urllib.request.Request(url)

    # Perform the request
    try:
        response = urllib.request.urlopen(request, context=ctx)
    except:
        message = "FAILED can_access_login_form"
        message += " : Exception thrown by urlopen. \n"
        message += "The server is likely not "
        message += "accessible at " + server + "\n"
        message += "The provided URL should include protocol, host and port \n"
        message += "e.g. http://127.0.0.1:5000"
        print(message)

        exit()

    # Read the response
    response_data = response.read()

    # Print the response
    # print(response_data.decode('utf-8'))

    # using the BeautifulSoup module
    soup = BeautifulSoup(response_data, 'html.parser')

    titleStr = ''

    for title in soup.find_all('title'):
        titleStr = title.get_text()

    if titleStr == "Log in" :
        print("PASSED can_access_login_form")

        return True
    else :
        message = "FAILED can_access_login_form"
        message += " : Expecting page title to be 'Log in'."
        print(message)

        return False

def can_log_in_and_receive_expected_response(username, password):
# Submits a valid username and password and tests for the return
# of a session cookie.
    url = server + '/login'

    # Create a cookie jar to handle cookies and session
    cookie_jar = http.cookiejar.CookieJar()

    # Create a cookie processor
    cookie_processor = urllib.request.HTTPCookieProcessor(cookie_jar)

    # Build an opener with the cookie processor
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), 
        cookie_processor
    )

    # Data to be sent to the form
    data = {
        'username': username,
        'password': password,
        'submit': 'submit'
    }

    # Encode the data
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')

    # Create a request object
    request = urllib.request.Request(url, encoded_data)

    # Perform the request
    response = opener.open(request)

    # Extract the session from the cookie jar
    session = extract_cookie_from_cookie_jar(cookie_jar, 'session')

    if session is not None :
        print("PASSED can_log_in_and_receive_expected_response")
        # Since we might need a valid session cookie for other tests,
        # we sill store this in the global variable, session_cookie.
        # However this cookie is signed by flask and can't actually be read
        # directly. We can only return it in the header of subsequent requests.
        global session_cookie 
        session_cookie = session

        return True
    
    message = "FAILED can_log_in_and_receive_expected_response"
    message += " : No session cookie received."
    print(message)

    return False

def cookie_is_set_with_httponly_secure_samesite_strict(username, password):
# Submits a valid username and password and tests for the 
# presence of 'SameSite=Strict', 'HttpOnly' and 'Secure' in the header.
    url = server + '/login'

    # Data to be sent to the form
    data = {
        'username': username,
        'password': password,
        'submit': 'submit'
    }

    # Encode the data
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')

    # Create a request object
    request = urllib.request.Request(url, encoded_data)

    # Perform the request
    response = urllib.request.urlopen(request, context=ctx)

    # Get the Set-Cookie header
    set_cookie_header = str(response.info().get_all('Set-Cookie'))

    if set_cookie_header.find("session") == -1:
        message = "FAILED cookie_is_set_with_httponly_secure_samesite_strict"
        message += " : No session cookie set. Couldn't log in?"
        print(message)

        return False
    
    test_passed = True
    message = ''

    if set_cookie_header.find("SameSite=Strict") == -1:
        message += " : Could not find 'SameSite=Strict'."
        test_passed = False
    
    if set_cookie_header.find("HttpOnly") == -1:
        message += " : Could not find 'HttpOnly'."
        test_passed = False
    
    if set_cookie_header.find("Secure") == -1:
        message += " : Could not find 'Secure'."
        test_passed = False
    
    if test_passed :
        message = "PASSED cookie_is_set_with_httponly_secure_samesite_strict"
        print(message)

        return True
    
    print("FAILED cookie_is_set_with_httponly_secure_samesite_strict", message)

    return False

def restricted_route_redirects_to_login_when_not_logged_in():
# Performs a get request for /restricted without a valid session cookie and 
#    checks if the title in the HTML response is 'Please log in'
    url = server + '/restricted'

    # Create a request object
    request = urllib.request.Request(url)

    # Perform the request
    response = urllib.request.urlopen(request, context=ctx)

    # Read the response
    response_data = response.read()

    # Print the response
    # print(response_data.decode('utf-8'))

    # Using the BeautifulSoup module to find the contents of the title tag
    soup = BeautifulSoup(response_data, 'html.parser')
    titleStr = ''
    for title in soup.find_all('title'):
        titleStr = title.get_text()

    if titleStr == "Log in" :
        print("PASSED restricted_route_redirects_to_login_when_not_logged_in")

        return True
    else :
        message = "FAILED "
        message += "restricted_route_redirects_to_login_when_not_logged_in"
        message += " : Page title isn't 'Log in'. Expecting redirect to /login."
        print(message)

        return False

def can_access_restricted_page_when_logged_in():
# Performs a get request for /restricted with a logged in session cookie.
# Expects the page title to be 'Restricted'.
    url = server + '/restricted'

    if (session_cookie == '') :
        message = "FAILED can_access_restricted_page_when_logged_in : "
        message += "Don't have a session cookie. Couldn't log in?"
        print (message)

        return False
    
    # Create a request object
    request = urllib.request.Request(url)

    # Add a session cookie with a valid login
    request.add_header('cookie', 'session=' + session_cookie)

    # Perform the request
    response = urllib.request.urlopen(request, context=ctx)

    soup = BeautifulSoup(response.read().decode('utf-8'), 'html.parser')
    
    titleStr = ''

    for title in soup.find_all('title'):
        titleStr = title.get_text()
    
    if titleStr != "Restricted" :
        message = "FAILED can_access_restricted_page_when_logged_in"
        message += " : Page title isn't 'Restricted'."
        print(message)

        return False
    
    print("PASSED can_access_restricted_page_when_logged_in")

    return True

def can_request_and_receive_aphorisms_when_logged_in():
# Requires a valid session cookie, so call 
#    can_log_in_and_receive_expected_response before this function.
# Get our CSRF token by requesting /restricted by GET, then submit it by POST.
# This CSRF token is also in the session cookie.
    url = server + '/restricted'

    if (session_cookie == '') :
        message = "FAILED can_request_and_receive_aphorisms_when_logged_in : "
        message += "Don't have a session cookie. Couldn't log in?"
        print (message)

        return False
    
    csrf_token = ''
    
    # Create a request object
    request = urllib.request.Request(url)

    # Add a session cookie with a valid login
    request.add_header('cookie', 'session=' + session_cookie)

    # Perform the request
    response = urllib.request.urlopen(request, context=ctx)

    # Get the csrf token from the returned html
    soup = BeautifulSoup(response.read().decode('utf-8'), 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
    
    # Now we can make a post request with that CSRF token

    # Data to be sent to the form
    form_data = {
        'csrf_token': csrf_token,
        'submit': 'submit'
    }

    # Encode the data
    encoded_data = urllib.parse.urlencode(form_data).encode('utf-8')

    # Create a request object with the form data
    request = urllib.request.Request(url, encoded_data)

    # Add a session cookie with a valid login
    request.add_header('cookie', 'session=' + session_cookie)

    # Perform the request
    response = urllib.request.urlopen(request, context=ctx)

    # To test if we're successful we're going to check that the page title 
    # is 'Aphorisms from The Zen of Python' and that 
    # the first three paragraph elements contain aphorisms within 
    # a list of acceptable aphorisms.
    soup = BeautifulSoup(response.read().decode('utf-8'), 'html.parser')
    
    titleStr = ''

    for title in soup.find_all('title'):
        titleStr = title.get_text()
    
    if titleStr != "Aphorisms from The Zen of Python" :
        print("FAILED can_request_and_receive_aphorisms_when_logged_in")

        return False

    # Title is as expected, so we will check the first three paragraph elements

    # Possible contents of a <p> element that will be treated as an aphorism.
    acceptable_aphorisms = [
        "Beautiful is better than ugly.", 
        "Simple is better than complex.",
        "Explicit is better than implicit.",
        "Beautiful is better than Ugly.", 
        "Simple is better than Complex.",
        "Explicit is better than Implicit.",
        "b'Beautiful is better than?' b'Ugly.'",
        "b'Simple is better than?' b'Complex.'",
        "b'Explicit is better than?' b'Implicit.'"
    ]
    
    paragraphs = soup.find_all('p')

    if paragraphs is None:
        message = "FAILED can_request_aphorism_when_logged_in"
        message += " : No acceptable aphorisms in page."
        print(message)

        return False
    
    for i in range(1) :

        if paragraphs[i].get_text() not in acceptable_aphorisms : 
            message = "FAILED can_request_and_receive_aphorisms_when_logged_in"
            message += " : '" + paragraphs[i].get_text() + "' Is not one of; "
            for aphorism in acceptable_aphorisms:
                message += "'" + aphorism + "' "
            print(message)

            return False 
   

        
    #OK, there's probably three aphorisms returned, in the required template.
    print("PASSED can_request_and_receive_aphorisms_when_logged_in")
    
    return True

def can_log_out_and_receive_expected_response():
# Requires a logged in session. 
#    Call can_log_in_and_receive_expected_response first.
# Performs a get request for /logout and expects the page title to be 
# 'Logged out'. Then expects to be denied access to restricted with the session.
    
    if (session_cookie == '') :
        message = "FAILED can_log_out : "
        message += "Don't have a session cookie. Couldn't log in?"
        print (message)

        return False

    url = server + "/logout"

    # Create a request object
    request = urllib.request.Request(url)

    # Add a session cookie with a valid login
    request.add_header('cookie', 'session=' + session_cookie)

    # We're getting an updated cooke, so create a cookie jar to handle it
    cookie_jar = http.cookiejar.CookieJar()

    # Create a cookie processor
    cookie_processor = urllib.request.HTTPCookieProcessor(cookie_jar)

    # Build an opener with the cookie processor
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), 
        cookie_processor
    )

    # Perform the request with the opener
    response = opener.open(request)
    
    # Extract the session from the cookie jar
    updated_session = extract_cookie_from_cookie_jar(cookie_jar, 'session')

    if updated_session is None:
        updated_session = ''
    
    # Using the BeautifulSoup module
    soup = BeautifulSoup(response.read().decode('utf-8'), 'html.parser')

    titleStr = ''

    for title in soup.find_all('title'):
        titleStr = title.get_text()

    if titleStr != "Logged out" :
        message = "FAILED can_log_out_and_receive_expected_response"
        message += " : Page title isn't 'Logged out'."
        print(message)

        return False
    
    url = server + '/restricted'

    # Create a request object
    request = urllib.request.Request(url)

    # Add the updated session cookie which should be cleared
    request.add_header('cookie', 'session=' + updated_session)

    # Perform the request
    response = urllib.request.urlopen(request, context=ctx)

    # Using the BeautifulSoup module
    soup = BeautifulSoup(response.read().decode('utf-8'), 'html.parser')
    titleStr = ''
    for title in soup.find_all('title'):
        titleStr = title.get_text()

    if titleStr != "Log in" :
        message = "FAILED can_log_out_and_receive_expected_response"
        message += " : Page title isn't 'Log in'."
        message += " Should redirect to /login and find that title."
        print(message)

        return False

    print("PASSED can_log_out_and_receive_expected_response")

    return True

if __name__ == "__main__" :
    parser = argparse.ArgumentParser(
        description='CSC2330 Assignment 3 Test HTTP/S client')
    parser.add_argument('--url', help='Server URL e.g. http://127.0.0.1:5000',
                        type=str, required=True)
    parser.add_argument('--username', metavar='username', 
                        type=str, required=True,
                        help='A username in app_improved.py e.g. u1234567.')
    parser.add_argument('--password', metavar='password', 
                        type=str, required=True,
                        help='The password associated with the username/')
    args = parser.parse_args()
    server = args.url

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ----- Call your test functions here -----
    can_access_login_form()
    can_log_in_and_receive_expected_response(args.username, args.password)
    restricted_route_redirects_to_login_when_not_logged_in()
    can_access_restricted_page_when_logged_in()
    can_request_and_receive_aphorisms_when_logged_in()
    can_log_out_and_receive_expected_response()
    cookie_is_set_with_httponly_secure_samesite_strict(args.username, args.password)
