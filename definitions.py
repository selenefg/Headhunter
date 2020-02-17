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

# Transfer-Encoding: xchunked

# Transfer-Encoding : chunked

# Transfer-Encoding: chunked
# Transfer-Encoding: x

# Transfer-Encoding:[tab]chunked

# [space]Transfer-Encoding: chunked

# X: X[\n]Transfer-Encoding: chunked

# Transfer-Encoding
# : chunked