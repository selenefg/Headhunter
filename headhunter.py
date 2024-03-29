import argparse
import requests
import logging
from requests.auth import HTTPDigestAuth
from requests.auth import HTTPBasicAuth
import urllib
import sys
from definitions import *
from utilities import *

def report_on_missing_headers(url, require_description, require_headers, auth):
    req = requests.get(url, auth = auth)
    print_underlined("Analyzing headers\n")
    for header in SecHeaders:
        if require_description:
            description = "\nDescription:" + SecHeadersDescriptions[header]
            tabbed = True
        else:
            description = ""
            tabbed = False
        report(header, 
               lambda h: HTTPHeaderEntries[h] not in req.headers, 
               HTTPHeaderEntries[header], 
               HTTPHeaderEntries[header] + " not found" + description,
               tabbed)
    print('')
    if require_headers: 
        print_underlined("Printing headers\n")
        for element in req.headers:
            print(element + ": " + req.headers[element])
        print('')

def report_on_cookie_attributes(url, auth):
    print_underlined("Analyzing cookies\n")
    cookie_tests = [
        [lambda c: c.secure, "Secure", "Secure attribute missing"],
        [lambda c: 'Httponly' in c._rest.keys(), "HTTPOnly", "HTTPOnly attribute missing"],
        [lambda c: c.domain_initial_dot, "Well defined domain", "Loosely defined domain"],
    ] 
    req =  requests.get(url, auth=auth)
    for cookie in req.cookies:
        print("Name:" + cookie.name)
        print("Value:" + cookie.value)
        for test in cookie_tests:
            cookie_report(cookie, test[0], test[1], test[2])
    print('')

def report_on_added_cookies(url, cookie):
    print_underlined("Adding \"" + cookie + "\"cookie\n")
    response = urllib.request.Request(url)
    response.add_header("New cookie", cookie)
    print(response.header_items())

def report_on_added_headers(url, header):
    print_underlined("Adding \"" + header + "\" header\n")
    response = urllib.request.Request(url)
    response.add_header(header)
    print(response.headers)

def report_on_transfer_encoding_header(url):
    print_underlined("Adding Transfer-Enconding header\n")
    response = urllib.request.Request(url)
    for header in TransferEncondingHeader:
        if response.has_header(header) == True: 
            print("Header already added")
            exit()
    response.add_header(TransferEncondingHeader["1"][0], TransferEncondingHeader["1"][1])
    print(response.headers)

def main(arg):
    logging.basicConfig(level=logging.ERROR)
    parser = argparse.ArgumentParser()
    parser.add_argument('-x', '--proxy',nargs='?',help="Set the proxy server (example: 192.168.1.1:8080)")
    parser.add_argument('-d', '--definitions', action='store_true', help="Print the purpose and functionality of each missing header")
    parser.add_argument('-H', '--printheaders',action='store_true', help="Print the security headers found")
    parser.add_argument('-U', '--basicuser', nargs='?', help="Username for basic-auth")
    parser.add_argument('-P', '--basicpass', nargs='?', help="Password for basic-auth")
    parser.add_argument('-u', '--digestuser', nargs='?', help="Username for digest-auth")
    parser.add_argument('-p', '--digestpass', nargs='?', help="Password for digest-auth")
    parser.add_argument('-c', '--addcookies', nargs='?', help="Add a custom cookie")
    parser.add_argument('-a', '--addheaders', nargs='?', help="Add a custom HTTP header")
    parser.add_argument('-t', '--transferenconding', action='store_true', help="Perform an HTTP request smuggling attack by obfuscating the TE header")

    args, unknown = parser.parse_known_args()
    if len(arg) > 1:        
        url = arg[1]
    else:
        sys.exit('One URL argument required')
    try: 
        (requests.get(url))
    except: 
        sys.exit("URL failed. Did you add 'https://'?")

    if args.basicuser is not None:
        auth = HTTPBasicAuth(args.basicuser, args.basicpass)
    elif args.digestuser is not None:
        auth = HTTPDigestAuth(args.digestuser, args.digestpass)
    else:
        auth = None

    
    if args.proxy is not None: 
        session = requests.session()
        print(session.get(url, proxies=args.proxy))
    
    print(requests.get(url, auth=auth))
    report_on_missing_headers(url, args.definitions, args.printheaders, auth)
    report_on_cookie_attributes(url, auth)
    if args.addcookies: report_on_added_cookies(url, args.addcookies)
    if args.addheaders: report_on_added_headers(url, args.addheaders)
    #if args.transferenconding: report_on_transfer_encoding_header(url)

if __name__ == '__main__':
    main(sys.argv)
    