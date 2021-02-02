# frozen_string_literal: true

# Support
require "jekyll-secinfo/logger" 

CONFIG_NAME = 'jekyll-secinfo'

module Jekyll::Secinfo
	class Config
				
		def self.get(site_config, page)
			config = { "cve" => {} }
			if site_config && site_config.key?(CONFIG_NAME) 
				#config["site"] = site_config[CONFIG_NAME]
				if site_config[CONFIG_NAME].key?("cve") && site_config[CONFIG_NAME]["cve"]
					if site_config[CONFIG_NAME]["cve"].key?("style") && site_config[CONFIG_NAME]["cve"]["style"]
						config["cve"]["style"] = site_config[CONFIG_NAME]["cve"]["style"]
					end
					if site_config[CONFIG_NAME]["cve"].key?("url") && site_config[CONFIG_NAME]["cve"]["url"]
						config["cve"]["url"] = site_config[CONFIG_NAME]["cve"]["url"]
					end
				end
			end

			if page.key?(CONFIG_NAME) && page[CONFIG_NAME]
	    		if page[CONFIG_NAME].key?("cve") && page[CONFIG_NAME]["cve"]
	    			if page[CONFIG_NAME]["cve"].key?("style") && page[CONFIG_NAME]["cve"]["style"]
	    				config["cve"]["style"]=page[CONFIG_NAME]["cve"]["style"]
	    				config["cve"]["url"]=nil
		    		end
	    			if page[CONFIG_NAME]["cve"].key?("url") && page[CONFIG_NAME]["cve"]["url"]
	    				config["cve"]["url"]=page[CONFIG_NAME]["cve"]["url"]
	    				config["cve"].delete("style")
		    		end
		    	end
			end			

			if not config["cve"]["url"]  
				case config["cve"]["style"]
				when "mitre"
					config["cve"]["url"] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"
				when "cvedetails"
					config["cve"]["url"] = "https://www.cvedetails.com/cve/CVE-%s/"
				when "nvd"
					config["cve"]["url"] = "https://nvd.nist.gov/vuln/detail/CVE-"
				else
					# Unknown CVE style using 'mitre'-style instead
					config["cve"]["url"] = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"
				end
			end

			return config
		end #get_config

	end #Config
end #module
