# cves_search
This script :
1. Find public github exploits related to a specific product and version
1. Find public github exploits related to a particular CVE
2. Take the kernel version of Linux, find CVEs associted with that version than can be used for **privilege escalation** on NIST vulnerability database and find public exploits on github associated with each CVE identified

## How to run 
### Find public github exploits related to a specific product and version
![Get public github exploit for a specific product and version](product_search.png)

### Find public github exploits related to a particular CVE
![Get public github exploit for CVE](cve_search.png)
  
### Find public github exploits for privilege escalation related to a linux kernel 
- Get the Linux kernel version using `uname -v`
  ![Get Linux Kernel version](uname.png)
  
- Submit the version to the script
  
  ![Get github links of each CVE identified](kernel_search.png)
