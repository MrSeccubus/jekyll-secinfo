# Jekyll Secinfo

This Jekyll pluging provides a tag and filter that turns references to security related info (currently only CVEs) into clickable links.


[![<MrSeccubs>](https://circleci.com/gh/MrSeccubus/jekyll-secinfo.svg/tree/main?style=svg)](https://app.circleci.com/pipelines/github/MrSeccubus/jekyll-secinfo?branch=main) 
[![Gem Version](https://badge.fury.io/rb/jekyll-secinfo.svg)](https://badge.fury.io/rb/jekyll-secinfo)
[![Maintainability](https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/maintainability)](https://codeclimate.com/github/codeclimate/codeclimate/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/test_coverage)](https://codeclimate.com/github/codeclimate/codeclimate/test_coverage)

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

As a tag `{% cve CVE-2019-19781 %}` or as a filter `{{ "cve-2019-19781" | cve }}`

For CVE multiple formats are accepted:
* Full CVE in lower or upper case e.g. `CVE-2019-19781` or `cve-2019-19781`
* Just the number e.g. `2019-19781`

## Result

By default the plugin will output the following code

```markup
<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19781" class="cve">CVE-2019-19781</a>
```

## Configuration

The behaviour of this plugin can be configured in `_config.yml`

```yml
jekyll-secinfo: 
  cve: 
    style: mitre    # Supported styles are mitre, nvd and cvedetails
    url:            # Style is ignored if a custom URL is defined.
```

You can also put these values in the front matter of a page to override the values in `_config.yml` for a specific page.

### Styles

For CVE's the style influences the way a tag or filter is rendered. This is how this input `{% cve CVE-2019-19781 %}` or as a filter `{{ "CVE-2019-19781" | cve }}` will be rendered in different styles:

mitre
```markup
<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19781" class="cve">CVE-2019-19781</a>
```

mitre
```markup
<a href="https://nvd.nist.gov/vuln/detail/CVE-2019-19781" class="cve">CVE-2019-19781</a>
```

mitre
```markup
<a href="https://www.cvedetails.com/cve/CVE-2019-19781/" class="cve">CVE-2019-19781</a>
```

### Using your own URL

You can specify a custom URL to be used as well. If the url includes `%s` this will be substituted with the number part of the CVE once. Otherwise the number part of the CVE will be appended to the url.

```markup
jekyll-secinfo: 
  cve: 
    url: http://localhost:4500/CVE-%s.html
---
{% cve 1999-9999 %}
```

Will reneder as
```markup
<p><a href="http://localhost:4500/CVE-1999-99999.html" class="cve">CVE-1999-99999</a></p>
```

