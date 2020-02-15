import argparse
import requests
from requests.auth import HTTPBasicAuth
import sys
import colorama
from colorama import Fore, Style

SecHeaders = {
    "STS": "strict-transport-security",
    "XFrame": "X-Frame-Options",
    "XSS": "XSS Protection",
    "XContent": "X-Content-Type-Options",
    "Content": "Content-Security-Policy",
    "XPerm": "X-Permitted-Cross-Domain-Policies",
    "Referrer": "Referrer-Policy",
}

SecHeadersDescriptions = {

    "STS": "\n\tHTTP Strict Transport Security is an excellent feature to support on your site and strengthens\n"
           "\tyour implementation of TLS by getting the User Agent to enforce the use of HTTPS.\n"
           "\tRecommended value: \"strict-transport-security: max-age=31536000; includeSubDomains\".",
    "XFrame": "\n\tX-Frame-Options tells the browser whether you want to allow your site to be framed or not.\n"
              "\tBy preventing a browser from framing your site you can defend against attacks like clickjacking.\n"
              "\tRecommended value: \"x-frame-options: SAMEORIGIN\".",
    "XSS": "\n\tX-XSS-Protection sets the configuration for the cross-site scripting filter built into most browsers.\n"
           "\tRecommended value: \"X-XSS-Protection: 1; mode=block\".",
    "XContent": "\n\tX-Content-Type-Options stops a browser from trying to MIME-sniff the content type and forces it\n"
                "\tto stick with the declared content-type.\n"
                "\tThe only valid value for this header is: \"X-Content-Type-Options: nosniff\".",
    "Content": "\n\tContent Security Policy is an effective measure to protect your site from XSS attacks.\n"
               "\tBy whitelisting sources of approved content, you can prevent the browser from loading malicious assets.",
    "XPerm": "TO-DO",#TODO
    "Referrer": "TO-DO",#TODO
}

def report (thing, condition, success, failure, tabbed_failure = False):
    green_plus = Fore.GREEN + "[+] " + Style.RESET_ALL
    red_exclamation = Fore.RED + "[!] " + Style.RESET_ALL
    if condition(thing):
        print(green_plus + success)
    else: 
        if tabbed_failure:
            print("\t", end='')
        print(red_exclamation + failure)

def report_on_missing_headers(url):
    req =  requests.get(url)
    for header in SecHeaders:
        report(header, 
               lambda h: SecHeaders[h] not in req.headers, 
               SecHeaders[header] + "\n", 
               SecHeaders[header] + " not found" + Fore.RED + "\n\tDefinition:" + Style.RESET_ALL + "\t" +SecHeadersDescriptions[header] + "\n",
               True)


def report_on_cookies(url):
    cookie_tests = [
        [lambda c: c.secure, "Secure", "Secure attribute missing"],
        [lambda c: 'httponly' in c._rest.keys(), "HTTPOnly", "HTTPOnly attribute missing"],
        [lambda c: c.domain_initial_dot, "Well defined domain", "Loosely defined domain"],
    ] 
    req =  requests.get(url)
    for cookie in req.cookies:
        print("\nName:" + cookie.name + "\nValue:" + cookie.value)
        for test in cookie_tests:
            report(cookie, test[0], test[1], test[2])

def basic_auth(url, username, password):
    req = requests.get(url, auth=HTTPBasicAuth(username, password))
    if req.status_code == 200:
        print("Username: " + str(username) + " / Password: " + str(password))
        print(Fore.GREEN + "[Success] " + Style.RESET_ALL + "status code " + str(req.status_code))
    else: print(Fore.RED + "[Error] " + Style.RESET_ALL + "status code " + str(req.status_code))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',required=True,nargs='+',help="The URL to be scanned")
    parser.add_argument('-U','--username',required=False,nargs='+',help="Username for basic-auth")
    parser.add_argument('-P','--password',required=False,nargs='+',help="Password for basic-auth")
    #parser.add_argument('-x PROXY', '--proxy PROXY',required=False,nargs='+',help="Set the proxy server (example: 192.168.1.1:8080)")
    #parser.add_argument('-D', '--definitions',required=False,nargs='+',help="Print the purpose and functionality of each missing header")

    args = parser.parse_args()
    
    for url in args.url:
        if not 'https://' in url: url = "https://" + url
        print("======Analizing headers...======\n")
        report_on_missing_headers(url)
        print("======Analizing cookies...======\n")
        report_on_cookies(url)
        print("\n======Testing basic-auth...======\n")
        basic_auth(url, args.username, args.password)

if __name__ == '__main__':
    main()
