# External
require "jekyll"
require "jekyll-secinfo/version"

# Support
require "jekyll-secinfo/logger" 
require "jekyll-secinfo/config" 

module Jekyll::Secinfo
  class Cve
    
    def self.to_link(text, site, page)
      #Logger.log(context)
      config = Jekyll::Secinfo::Config.get(site, page)
      m = text.match(/^(CVE-|cve-)?(\d{4}-\d{4,})/) # See https://cve.mitre.org/cve/identifiers/syntaxchange.html
      if m
        if config["cve"]["url"] =~ /\%s/
          url=config["cve"]["url"] % m[2]
        else
          url="#{config["cve"]["url"]}#{m[2]}"
        end
        return "<a href='#{url}' class='cve secinfo'>CVE-#{m[2]}</a>"
      else
        return nil
      end
    end
  end

  class CveTag < Liquid::Tag

    def initialize(tagName, text, tokens)
      super
      @text = text
    end

    def render(context)
      cve_text = @text.strip
      out = Cve.to_link(cve_text, context["site"], context["page"])
      return out if out
      return @text
    end

  end

  module CveFilter
    def cve(cvetxt, niets = nil)
      if cvetxt
        link = Cve.to_link(cvetxt, @context.registers[:site].config, @context.registers[:page])
        if link
          return link
        else
          return cvetxt
        end
      else
        return ""
      end
    end
  end

  Liquid::Template.register_tag("cve", Jekyll::Secinfo::CveTag)
  Liquid::Template.register_filter(CveFilter)

end