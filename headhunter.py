import argparse
import requests
from requests.auth import HTTPBasicAuth
import urllib
import sys
from definitions import *
from utilities import *

def report_on_missing_headers(url, require_description, require_headers):
    req = requests.get(url)
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

def report_on_cookies(url):
    print_underlined("Analyzing cookies\n")
    cookie_tests = [
        [lambda c: c.secure, "Secure", "Secure attribute missing"],
        [lambda c: 'httponly' in c._rest.keys(), "HTTPOnly", "HTTPOnly attribute missing"],
        [lambda c: c.domain_initial_dot, "Well defined domain", "Loosely defined domain"],
    ] 
    req =  requests.get(url)
    for cookie in req.cookies:
        print("Name:" + cookie.name)
        print("Value:" + cookie.value)
        for test in cookie_tests:
            report(cookie, test[0], test[1], test[2])
    print('')

def report_on_basic_auth(url, username, password):
    print_underlined("Testing basic_auth\n")
    req = requests.get(url, auth=HTTPBasicAuth(username, password))
    if req.status_code == 200:
        print("Username: " + str(username) + " / Password: " + str(password))
        print(Fore.GREEN + "[Success] " + Style.RESET_ALL + "status code " + str(req.status_code))
    else: 
        print(Fore.RED + "[Error] " + Style.RESET_ALL + "status code " + str(req.status_code))
    print('')

def add_header(url, header):
    print_underlined("Adding \"" + header + "\" header\n")
    response = urllib.request.Request(url)
    response.add_header(header)
    print(response.headers)

def add_transfer_encoding_header(url):
    print_underlined("Adding Transfer-Enconding header\n")
    response = urllib.request.Request(url)
    for header in TransferEncondingHeader:
        if response.has_header(header) == True: 
            print("Header already added")
            exit()
    response.add_header(TransferEncondingHeader["1"][0], TransferEncondingHeader["1"][1])
    print(response.headers)

def main(arg):
    parser = argparse.ArgumentParser()
    #parser.add_argument('-x PROXY', '--proxy PROXY',required=False,nargs='+',help="Set the proxy server (example: 192.168.1.1:8080)")
    parser.add_argument('-d', '--definitions', action='store_true', help="Print the purpose and functionality of each missing header")
    parser.add_argument('-H', '--printheaders', action='store_true', help="Print the security headers found")
    parser.add_argument('-U', '--username', nargs='+', help="Username for basic-auth")
    parser.add_argument('-P', '--password', nargs='+', help="Password for basic-auth")
    parser.add_argument('-a', '--addheader', nargs='?', help="Add a custom HTTP header")
    parser.add_argument('-t', '--transferenconding', action='store_true', help="Perform an HTTP request smuggling attack by obfuscating the TE header")

    args, unknown = parser.parse_known_args()
    
    if len(arg) > 1:        
        url = arg[1]
    else:
        sys.exit('One URL argument required')
    try: 
        (requests.get(url))
    except: 
        sys.exit("URL failed")
    
    print(requests.get(url))
    report_on_missing_headers(url, args.definitions, args.printheaders)
    report_on_cookies(url)
    if args.username or args.password: report_on_basic_auth(url, args.username, args.password)
    if args.addheader: add_header(url, args.addheader)
    #if args.transferenconding: add_transfer_encoding_header(url)

if __name__ == '__main__':
    main(sys.argv)