# security-advisory-client
MidnightBSD security advisory client


This client allows you to check installed packages for security vulnerabilities by comparing data to the NIST NVD database. It uses an open REST API. 

The client now communicates with the REST API over HTTPS to hide snooping of software.  It also intentionally does not send the version number to the API that you're interested in.  
