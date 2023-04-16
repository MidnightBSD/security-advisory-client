# security-advisory-client
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Flaffer1%2Fsecurity-advisory-client.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Flaffer1%2Fsecurity-advisory-client?ref=badge_shield)

MidnightBSD security advisory client


This client allows you to check installed packages for security vulnerabilities by comparing data to the NIST NVD database. It uses an open REST API. 

The client now communicates with the REST API over HTTPS to hide snooping of software.  It also intentionally does not send the version number to the API that you're interested in.  

## Installation

Via mports
cd /usr/mports/security/security-advisory-client
make install clean

Via package:
mport install security-advisory-client

## Run it
sudo /usr/local/bin/advisory.pl

It can also run out of the daily periodic scripts and results emailed to you. Simply add it to the /etc/periodic.conf file as
daily_status_security_advisorymport_enable="YES"


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Flaffer1%2Fsecurity-advisory-client.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Flaffer1%2Fsecurity-advisory-client?ref=badge_large)
