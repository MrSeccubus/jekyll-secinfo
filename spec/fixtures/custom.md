---
layout: default
title: Custom style
jekyll-secinfo: 
  cve: 
    style: nvd
    url: https://localhost/%s/details
  cwe: 
    style: nvd
    url: https://localhost/%s/details
  divd: 
    url: https://localhost/%s/details
---

full {% cve CVE-2020-8200 %} full
lower {% cve cve-2018-20808 %} lower
number {% cve 2000-1206 %} number
invalid {% cve cve-invalid %} invalid

full {% cwe CWE-79 %} full
lower {% cwe cwe-787 %} lower
number {% cwe 20 %} number
invalid {% cwe cwe-invalid %} invalid

full {% divd DIVD-2020-00001 %} full
lower {% divd divd-2020-00002 %} lower
number {% divd 2020-00003 %} number
invalid {% divd divd-invalid %} invalid