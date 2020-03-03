SecHeaders = ["STS", "XFrame", "XSS", "XContent", "Content", "XPerm", "Referrer"]

HTTPHeaderEntries = {
  "STS": "strict-transport-security",
  "XFrame": "X-Frame-Options",
  "XSS": "X-XSS-Protection",
  "XContent": "X-Content-Type-Options",
  "Content": "Content-Security-Policy",
  "XPerm": "X-Permitted-Cross-Domain-Policies",
  "Referrer": "Referrer-Policy",
}

SecHeadersDescriptions = {
  "STS": "\n\tHTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect websites\n"
         "\tagainst protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers\n"
         "\t(or other complying user agents) should only interact with it using secure HTTPS connections, and never via\n"
         "\tthe insecure HTTP protocol."
         "\tRecommended value: \"strict-transport-security: max-age=31536000; includeSubDomains\".",
  "XFrame": "\n\tX-Frame-Options response header improve the protection of web applications against Clickjacking.\n"
            "\tIt declares a policy communicated from a host to the client browser on whether the browser must not\n"
            "\tdisplay the transmitted content in frames of other web pages.\n"
            "\tRecommended value: \"x-frame-options: SAMEORIGIN; allow-from: DOMAIN; deny\".",
  "XSS": "\n\tThis header enables the Cross-site scripting (XSS) filter in your browser.\n"
         "\tRecommended value: \"X-XSS-Protection: 1; mode=block\".",
  "XContent": "\n\tSetting this header will prevent the browser from interpreting files as something else than\n"
              "\tdeclared by the content type in the HTTP headers.\n"
              "\tThe only valid value for this header is: \"X-Content-Type-Options: nosniff\".",
  "Content": "\n\tA Content Security Policy (CSP) requires careful tuning and precise definition of the policy.\n"
             "\tIf enabled, CSP has significant impact on the way browsers render pages (e.g., inline JavaScript\n"
             "\tdisabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks,\n"
             "\tincluding Cross-site scripting and other cross-site injections.",
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
