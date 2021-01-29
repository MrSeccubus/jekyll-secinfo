# frozen_string_literal: true

# External 
require "jekyll"

# Support
require "jekyll-secinfo/logger" 

# Core
require "jekyll-secinfo/cve" 

module Jekyll::Secinfo
  Logger.display_info
end
