# frozen_string_literal: true

# Support
require "jekyll-secinfo/logger" 

CONFIG_NAME = 'jekyll-secinfo'
DEFAULT_CONFIG = {
	CONFIG_NAME => {
		"cve" => {
			"style" => "mitre"
		}
	}
}


module Jekyll::Secinfo
	class Config
		
		def self.get(site_config, page)
			config = DEFAULT_CONFIG
			if site_config
				config = config.merge(site_config) if site_config.key?(CONFIG_NAME)
			end
			if page.key?(CONFIG_NAME)
				fromdoc = { CONFIG_NAME => page[CONFIG_NAME] }
				config = config.merge(fromdoc)
			end

			if not config[CONFIG_NAME]["cve"].key?("url")
				case config[CONFIG_NAME]["cve"]["style"]
				when "mitre"
					config[CONFIG_NAME]["cve"]["url"] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"
				when "cvedetails"
					config[CONFIG_NAME]["cve"]["url"] = "https://www.cvedetails.com/cve/CVE-%s/"
				when "nvd"
					config[CONFIG_NAME]["cve"]["url"] = "https://nvd.nist.gov/vuln/detail/CVE-"
				else
					# Unknown CVE style unsing 'mitre'-style instead
					config[CONFIG_NAME]["cve"]["url"] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"
				end
			end

			return config[CONFIG_NAME]
		end #get_config

	end #Config
end #module
