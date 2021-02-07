# External
require "jekyll"
require "jekyll-secinfo/version"

# Support
require "jekyll-secinfo/logger" 
require "jekyll-secinfo/config" 

module Jekyll::Secinfo
  class Divd
    
    def self.to_link(text, site, page)
      #Logger.log(context)
      config = Jekyll::Secinfo::Config.get(site, page)

      m = text.match(/^(DIVD-|divd-)?(\d{4}\-\d+)/) 
      if m
        if config["divd"]["url"] =~ /\%s/
          url=config["divd"]["url"] % m[2]
        else
          url="#{config["divd"]["url"]}#{m[2]}"
        end
        return "<a href='#{url}' class='divd secinfo'>DIVD-#{m[2]}</a>"
      else
        return nil
      end
    end
  end

  class DivdTag < Liquid::Tag

    def initialize(tagName, text, tokens)
      super
      @text = text
    end

    def render(context)
      divd_text = @text.strip
      out = Divd.to_link(divd_text, context["site"], context["page"])
      return out if out
      return @text
    end

  end

  module DivdFilter
    def divd(divdtxt, niets = nil)
      if divdtxt
        link = Divd.to_link(divdtxt, @context.registers[:site].config, @context.registers[:page])
        if link
          return link
        else
          return divdtxt
        end
      else
        return ""
      end
    end
  end

  Liquid::Template.register_tag("divd", Jekyll::Secinfo::DivdTag)
  Liquid::Template.register_filter(DivdFilter)

end