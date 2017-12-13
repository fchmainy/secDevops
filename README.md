# secDevops

Jenkins and Ansible pipeline as code to demonstrate a full automatated pipeline with LB, SSL Offload and WAF automated configuration.

Few details here:
- steps:
  1. Deployment in QA env for unit testings. Learning and WAF policy tightening are done based on app spidering (whitelisting) and vulnerability scans (Server Technology Detection + vulnerabilities resolutions).
  2 Deployment in Production using the validated ASM Policy.

- IP addresses are dynamically requested from PHP IPAM (https://phpipam.net/) through its API.
- Unit tests and security tests are performed on QA:
         - The crawling is basically done using recursive WGet (next time I will use Selenium which will give me more accurate results). 
         - Security Scanning is done using W3AF (http://w3af.org/).

This leverages existing F5 ASM features and new features provided on v13 such as Layered Policy with policy inheritance, Server Technology Detection, enhancement on Policy Builder...

Here is a short video:
https://youtu.be/RpN9YdXtn_k
