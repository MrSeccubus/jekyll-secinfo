# Jekyll Secinfo

This Jekyll pluging provides a tag and filter that turns references to security related info (CVEs, CWEs and DIVD case numbers) into clickable links.


[![Build Status](https://img.shields.io/circleci/build/github/MrSeccubus/jekyll-secinfo/main)](https://circleci.com/gh/MrSeccubus/jekyll-secinfo)
[![Maintainability](https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/maintainability)](https://codeclimate.com/github/codeclimate/codeclimate/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/test_coverage)](https://codeclimate.com/github/codeclimate/codeclimate/test_coverage)
[![MIT License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://github.com/MrSeccubus/jekyll-secinfo/blob/main/LICENSE.txt)
[![Gem downloads](https://img.shields.io/gem/dt/jekyll-secinfo)](https://rubygems.org/gems/jekyll-secinfo)

## Installation

Add this line to your Gemfile:

```ruby
group :jekyll_plugins do
  gem "jekyll-secinfo"
end
```

And then execute:

    $ bundle

Alternatively install the gem yourself as:

    $ gem install jekyll-secinfo

and put this in your ``_config.yml`` 

```yaml
plugins: 
- jekyll-secinfo
# This will require each of these gems automatically.
```

## Usage

As a tag `{% cve CVE-2019-19781 %}` / `{% cwe CWE-78 %}` / `{% divd DIVD-2020-00001 %}` or as a filter `{{ "cve-2019-19781" | cve }}` / `{{ "cwe-787" | cwe }}` / `{{ "divd-2020-0001" | divd }}`

For CVEs, CWEs and DIVD cas number filters an tags multiple formats are accepted:
* Full CVE in lower or upper case e.g. `CVE-2019-19781`, `CVE-787`, `DIVD-2020-00001`, `cve-2019-19781`, `cve-787` or `divd-2020-00001`
* Just the number e.g. `2019-19781`, `787` or `2020-00001`

## Result

By default the plugin will output the following code

CVEs
```markup
<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19781" class="cve secinfo">CVE-2019-19781</a>
```

CWEs
```markup
<a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">
```

DIVD case
```markup
<a href="https://csirt.divd.nl/DIVD-2020-00001" class="divd secinfo">DIVD-2020-00001</a>
```

## Configuration

The behaviour of this plugin can be configured in `_config.yml`

```yml
jekyll-secinfo: 
  cve: 
     style: mitre   # Supported styles are mitre, nvd and cvedetails
     url:           # Style is ignored if a custom URL is defined.
   cwe
     style: mitre   # Supported styles are mitre and cvedetails
     url:           # Style is ignored if a custom URL is defined.
   divd:
     url:           # Custom URL for DIVD cases.
```

You can also put these values in the front matter of a page to override the values in `_config.yml` for a specific page.

### Styles

For CVEs and CWEs the style influences the way a tag or filter is rendered. This is how the following input will be rendered in different styles

input as tags
```markup
CVE: {% cve CVE-2019-19781 %}
CWE: {% cwe CWE-79 %}
```

input with filters:
```markup
CVE: {{ "CVE-2019-19781" | cve }}
CWE: {{ "cwe-79" | cwe }}
```


Mitre
```markup
CVE: <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19781" class="cve secinfo">CVE-2019-19781</a>
CWE: <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a>
```


CVE details
```markup
CVE: <a href="https://www.cvedetails.com/cve/CVE-2019-19781/" class="cve secinfo">CVE-2019-19781</a>
CWE: <a href="https://www.cvedetails.com/cwe-details/79" class="cwe secinfo">CWE-79</a>
```

NVD
```markup
CVE: <a href="https://nvd.nist.gov/vuln/detail/CVE-2019-19781" class="cve secinfo">CVE-2019-19781</a>
CWE: <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a>
```
(Since CWE doesn;t support the style `nvd` it falls back tot he default `mitre` style)

### Using your own URL

You can specify a custom URL to be used as well. If the url includes `%s` this will be substituted with the number part of the CVE once. Otherwise the number part of the CVE will be appended to the url.

```markup
jekyll-secinfo: 
  cve: 
    url: http://localhost:4500/CVE-%s.html
  cwe: 
    url: http://localhost:4500/CWE-
  divd:
    url: https://localhost:4000/cases/DIVD-
---
{% cve 1999-9999 %}
{% cve 79 %}
{{ "2020-00001" | divd }}
```

Will reneder as:
```markup
<p><a href="http://localhost:4500/CVE-1999-99999.html" class="cve secinfo">CVE-1999-99999</a>
<a href="http://localhost:4500/CWE-79" class="cwe secinfo">CVE-1999-99999</a>
<a href="https://localhost:4000/cases/DIVD-2020-00001" class="divd secinfo">DIVD-2020-00001</a></p>
```

