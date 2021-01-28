---
layout: default
title: Wierd filter page
jekyll-secinfo: 
  cve: 
    style: supercalifragicexpialidocious
---

full {{ "CVE-2020-8200" | cve }} full
lower {{ "cve-2018-20808" | cve }} lower
number {{ "2000-1206" | cve }} number
invalid {{ "cve-invalid" | cve }} invalid


