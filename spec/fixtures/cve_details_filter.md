---
layout: default
title: CVEdetails filter page
jekyll-secinfo: 
  cve: 
    style: cvedetails
  cwe: 
    style: cvedetails
---

full {{ "CVE-2020-8200" | cve }} full
lower {{ "cve-2018-20808" | cve }} lower
number {{ "2000-1206" | cve }} number
invalid {{ "cve-invalid" | cve }} invalid

full {{ "CWE-79" | cwe }} full
lower {{ "cwe-787" | cwe }} lower
number {{ "20" | cwe }} number
invalid {{ "cwe-invalid" | cwe }} invalid