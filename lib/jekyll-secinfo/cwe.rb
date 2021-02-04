# External
require "jekyll"
require "jekyll-secinfo/version"

# Support
require "jekyll-secinfo/logger" 
require "jekyll-secinfo/config" 

module Jekyll::Secinfo
  class Cwe
    
    def self.to_link(text, site, page)
      #Logger.log(context)
      config = Jekyll::Secinfo::Config.get(site, page)
      m = text.match(/^(CWE-|cwe-)?(\d+)/) 
      if m
        if config["cwe"]["url"] =~ /\%s/
          url=config["cwe"]["url"] % m[2]
        else
          url="#{config["cwe"]["url"]}#{m[2]}"
        end
        return "<a href='#{url}' class='cwe secinfo'>CWE-#{m[2]}</a>"
      else
        return nil
      end
    end
  end

  class CweTag < Liquid::Tag

    def initialize(tagName, text, tokens)
      super
      @text = text
    end

    def render(context)
      cwe_text = @text.strip
      out = Cwe.to_link(cwe_text, context["site"], context["page"])
      return out if out
      return @text
    end

  end

  module CweFilter
    def cwe(cwetxt, niets = nil)
      if cwetxt
        link = Cwe.to_link(cwetxt, @context.registers[:site].config, @context.registers[:page])
        if link
          return link
        else
          return cwetxt
        end
      else
        return ""
      end
    end
  end

  Liquid::Template.register_tag("cwe", Jekyll::Secinfo::CweTag)
  Liquid::Template.register_filter(CweFilter)

end