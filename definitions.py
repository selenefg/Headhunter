SecHeaders = ["STS", "XFrame", "XSS", "XContent", "Content", "XPerm", "Referrer"]

HTTPHeaderEntries = {
  "STS": "Strict-Transport-Security",
  "XFrame": "X-Frame-Options",
  "XSS": "X-XSS-Protection",
  "XContent": "X-Content-Type-Options",
  "Content": "Content-Security-Policy",
  "XPerm": "X-Permitted-Cross-Domain-Policies",
  "Referrer": "Referrer-Policy",
}

SecHeadersDescriptions = {
  "STS": "\nHTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites\n"
         "against protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers\n"
         "(or other complying user agents) should only interact with it using secure HTTPS connections, and never via\n"
         "the insecure HTTP protocol. \033[4mhttps://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers\033[0m\n"
         "Recommended value: \"strict-transport-security: max-age=31536000; includeSubDomains\".",
  "XFrame": "\nX-Frame-Options response header improve the protection of web applications against Clickjacking.\n"
            "It declares a policy communicated from a host to the client browser on whether the browser must not\n"
            "display the transmitted content in frames of other web pages. \033[4mhttps://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers\033[0m\n"
            "Recommended value: \"x-frame-options: SAMEORIGIN; allow-from: DOMAIN; deny\".",
  "XSS": "\nThis header enables the Cross-site scripting (XSS) filter in your browser. \033[4mhttps://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers\033[0m\n"
         "Recommended value: \"X-XSS-Protection: 1; mode=block\".",
  "XContent": "\nSetting this header will prevent the browser from interpreting files as something else than\n"
              "declared by the content type in the HTTP headers. \033[4mhttps://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers\033[0m\n"
              "The only valid value for this header is: \"X-Content-Type-Options: nosniff\".",
  "Content": "\nA Content Security Policy (CSP) requires careful tuning and precise definition of the policy.\n"
             "If enabled, CSP has significant impact on the way browsers render pages (e.g., inline JavaScript\n"
             "disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks,\n"
             "including Cross-site scripting and other cross-site injections. \033[4mhttps://wiki.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers\033[0m",
  "XPerm": "TO-DO",#TODO
  "Referrer": "TO-DO",#TODO
  #Public Key Pinning Extension for HTTP (HPKP)
  #X-Permitted-Cross-Domain-Policies
  #Expect-CT
  #Feature-Policy
}

TransferEncondingHeader = {
  "1": ["Transfer-Encoding:"," chunked"],
  "2": ["Transfer-Encoding :"," chunked"],
  "3": ["Transfer-Encoding:"," xchunked"],
  "4": ["Transfer-Encoding:"," x"],
  "5": ["Transfer-Encoding:","[tab]chunked"],
  "6": ["[space]Transfer-Encoding:"," chunked"],
  "7": ["X: X[\n]Transfer-Encoding:"," chunked"],
  "8": ["Transfer-Encoding\n:"," chunked"],
}
