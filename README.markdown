# Overview

Light-weight HTTP proxy server, used to reply with HTTP responses,
parsed from pcap-file.

Suppose a problem - you want to show user's web browsing, stored in pcap
file. First thing you do - fetches main requests from the pcap and then
direct em to the browser. In this point all embedded in the main request
objects (images, flash, javascript, css etc.) will be recursively requested by the
browser and somebody must answer with the data, already stored in the pcap
file. This proxy is exactly this body. You should launch it with
pcap-file as the parameter, direct browser to use the server as a
http-proxy and launch in this browser "main" requests.

Furthermore you can give the proxy commonly used fonts, css, javascript,
wich browsers often caches, so it may answer the data, not stored in the
pcap-file due to caching.

