import argparse
import requests
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
    "Referrer": "Referrer-Policy"
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
               "\tBy whitelisting sources of approved content, you can prevent the browser from loading malicious assets."
}

def FindMissingSecurityHeaders(url):
    req =  requests.get(url)
    for header in SecHeaders:
        if SecHeaders[header] in req.headers: print("\t" + Fore.RED + "[!] " + Style.RESET_ALL + SecHeaders[header] + " not found" +
                                                    Fore.RED + "\n\tDefinition:" + Style.RESET_ALL + "\t" +SecHeadersDescriptions[header] + "\n")
        else: print(Fore.GREEN + "[+] " + Style.RESET_ALL + SecHeaders[header] + "\n") 

def FindInsecureCookies(url):
    req =  requests.get(url)
    for cookie in req.cookies:
        print("\nName:" + cookie.name + "\nValue:" + cookie.value)

        if cookie.secure: print(Fore.GREEN + "[+] " + Style.RESET_ALL + "Secure")
        else: print(Fore.RED + "[!] " + Style.RESET_ALL + "Secure attribute missing") 

        if 'httponly' in cookie._rest.keys():print(Fore.GREEN + "[+] " + Style.RESET_ALL + "HTTPOnly")
        else: print(Fore.RED + "[!] " + Style.RESET_ALL + "HTTPOnly attribute missing") 

        if cookie.domain_initial_dot: print(Fore.GREEN + "[+] " + Style.RESET_ALL + "Well defined domain")
        else: print(Fore.RED + "[!] " + Style.RESET_ALL + "Loosely defined domain")  

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url',required=True,nargs='+',help="The URL to be scanned")
    #parser.add_argument('-x PROXY', '--proxy PROXY',required=False,nargs='+',help="Set the proxy server (example: 192.168.1.1:8080)")
    #parser.add_argument('-D', '--definitions',required=False,nargs='+',help="Print the purpose and functionality of each missing header")

    args = parser.parse_args()
    
    for url in args.url:
        if not 'https://' in url: sys.exit("missing \"https://\"")
        print("======Analizing headers...======\n")
        FindMissingSecurityHeaders(url)
        print("======Analizing cookies...======\n")
        FindInsecureCookies(url)

if __name__ == '__main__':
    main()
