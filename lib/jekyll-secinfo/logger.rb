# frozen_string_literal: true

require 'jekyll-secinfo/version'
require 'rainbow/refinement'

using Rainbow


module Jekyll::Secinfo
  class Logger
    def initialize(namespace)
      @namespace = namespace
    end

    def self.display_info
      self.log "Jekyll-Secinfo #{Jekyll::Secinfo::VERSION}"
      self.log 'A Jekyll plugin to provide clickability to security info like CVEs and CWEs.'
      self.log 'https://github.com/MrSeccubus/jekyll-secinfo'.underline
    end

    def self.log(content)
      if (content.is_a? String)
        self.output 'Jekyll Secinfo', content.bright
      else
        self.output 'Jekyll Secinfo', content.inspect.bright
      end
    end

    def self.output(title, content)
      puts "#{title.rjust(18)}: #{content}"
    end

    def log(content)
      if @namespace.nil?
        self.class.log content
      else
        self.class.log "[#{@namespace}] #{content}"
      end
    end
  end
end