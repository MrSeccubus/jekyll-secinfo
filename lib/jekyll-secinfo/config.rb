# frozen_string_literal: true

# Support
require "jekyll-secinfo/logger" 

CONFIG_NAME = 'jekyll-secinfo'

module Jekyll::Secinfo
	class Config
				
		def self.get(site_config, page)
			config = { 
				"cve" => {},
				"cwe" => {},
				"divd" => {}
			}

			# CVE

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
	    				config["cve"].delete("url")
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

			# CWE

			if site_config && site_config.key?(CONFIG_NAME) 
				if site_config[CONFIG_NAME].key?("cwe") && site_config[CONFIG_NAME]["cwe"]
					if site_config[CONFIG_NAME]["cwe"].key?("style") && site_config[CONFIG_NAME]["cwe"]["style"]
						config["cwe"]["style"] = site_config[CONFIG_NAME]["cwe"]["style"]
					end
					if site_config[CONFIG_NAME]["cwe"].key?("url") && site_config[CONFIG_NAME]["cwe"]["url"]
						config["cwe"]["url"] = site_config[CONFIG_NAME]["cwe"]["url"]
					end
				end
			end

			if page.key?(CONFIG_NAME) && page[CONFIG_NAME]
	    		if page[CONFIG_NAME].key?("cwe") && page[CONFIG_NAME]["cwe"]
	    			if page[CONFIG_NAME]["cwe"].key?("style") && page[CONFIG_NAME]["cwe"]["style"]
	    				config["cwe"]["style"]=page[CONFIG_NAME]["cwe"]["style"]
	    				config["cwe"].delete("url")
		    		end
	    			if page[CONFIG_NAME]["cwe"].key?("url") && page[CONFIG_NAME]["cwe"]["url"]
	    				config["cwe"]["url"]=page[CONFIG_NAME]["cwe"]["url"]
	    				config["cwe"].delete("style")
		    		end
		    	end
			end			

			if not config["cwe"]["url"]  
				case config["cwe"]["style"]
				when "mitre", "nvd"
					config["cwe"]["url"] = "https://cwe.mitre.org/data/definitions/%s.html"
				when "cvedetails"
					config["cwe"]["url"] = "https://www.cvedetails.com/cwe-details/"
				else
					# Unknown CWE style using 'mitre'-style instead
					config["cwe"]["url"] = "https://cwe.mitre.org/data/definitions/%s.html"
				end
			end

			# DIVD

			if site_config && site_config.key?(CONFIG_NAME) 
				if site_config[CONFIG_NAME].key?("divd") && site_config[CONFIG_NAME]["divd"]
					if site_config[CONFIG_NAME]["divd"].key?("url") && site_config[CONFIG_NAME]["divd"]["url"]
						config["divd"]["url"] = site_config[CONFIG_NAME]["divd"]["url"]
					end
				end
			end

			if page.key?(CONFIG_NAME) && page[CONFIG_NAME]
	    		if page[CONFIG_NAME].key?("divd")
	    			if page[CONFIG_NAME]["divd"]
		    			if page[CONFIG_NAME]["divd"].key?("url")
		    				if page[CONFIG_NAME]["divd"]["url"]
		    					config["divd"]["url"]=page[CONFIG_NAME]["divd"]["url"]
			    			else
			    				config["divd"].delete("url")
			    			end
			    		end
			    	else
			    		config["divd"] = {}
			    	end
		    	end
			end			

			if not config["divd"]["url"]  
				config["divd"]["url"] = "https://csirt.divd.nl/DIVD-"
			end      

			return config
		end #get_config

	end #Config
end #module
