---
layout: default
title: CVEdetails style
jekyll-secinfo: 
  cve: 
    style: cvedetails
  cwe: 
    style: cvedetails
---

full {% cve CVE-2020-8200 %} full
lower {% cve cve-2018-20808 %} lower
number {% cve 2000-1206 %} number
invalid {% cve cve-invalid %} invalid

full {% cwe CWE-79 %} full
lower {% cwe cwe-787 %} lower
number {% cwe 20 %} number
invalid {% cwe cwe-invalid %} invalid