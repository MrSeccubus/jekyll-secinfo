# frozen_string_literal: true

RSpec.describe(Jekyll::Secinfo) do
	Jekyll.logger.log_level = :error

	types = [ "default", "mitre", "weird", "nvd", "cvedetails", "custom" ]

    describe "Jekyll Site" do
    	types.each do |type|
        	describe "with config '#{type}'" do
          		before(:each) do
	        		@type = type
            		base_config = Jekyll.configuration(
				        "skip_config_files" => false,
				        "source"            => fixtures_dir,
        				"destination"       => fixtures_dir("_site"),
        				"jekyll-secinfo" 	=> {}
      				)
      				case type
      				when "default"
						@site = Jekyll::Site.new(base_config)
      				when "mitre"
						@site = Jekyll::Site.new(base_config.merge(
	      						"jekyll-secinfo" => {
	      							"cve" => {
	      								"style" => "mitre"
	      							}
	      						}
	      					)
						)
      				when "weird"
						@site = Jekyll::Site.new(base_config.merge(
	      						"jekyll-secinfo" => {
	      							"cve" => {
	      								"style" => "feiuyvineueaiuse"
	      							}
	      						}
	      					)
						)
      				when "nvd"
						@site = Jekyll::Site.new(base_config.merge(
	      						"jekyll-secinfo" => {
	      							"cve" => {
	      								"style" => "nvd"
	      							}
	      						}
	      					)
						)
      				when "cvedetails"
						@site = Jekyll::Site.new(base_config.merge(
	      						"jekyll-secinfo" => {
	      							"cve" => {
	      								"style" => "cvedetails"
	      							}
	      						}
	      					)
						)
      				when "custom"
						@site = Jekyll::Site.new(base_config.merge(
	      						"jekyll-secinfo" => {
	      							"cve" => {
	      								"url" => "https://localhost/%s/info.html"
	      							}
	      						}
	      					)
						)
      				end

				    @site.reset
				    @site.read
				    @site.render

					@index_page          	= find_by_title(@site.pages, "I'm a page")
					@mitre_page          	= find_by_title(@site.pages, "Mitre style")
					@weird_page          	= find_by_title(@site.pages, "Weird style")
					@nvd_page            	= find_by_title(@site.pages, "NVD style")
					@cvedetails_page     	= find_by_title(@site.pages, "CVEdetails style")
					@custom_page         	= find_by_title(@site.pages, "Custom style")

					@default_filter 		= find_by_title(@site.pages, "Default filter page") 
					@mitre_filter 			= find_by_title(@site.pages, "Mitre filter page") 
					@weird_filter 			= find_by_title(@site.pages, "Wierd filter page") 
					@nvd_filter 			= find_by_title(@site.pages, "NVD filter page") 
					@cvedetails_filter 		= find_by_title(@site.pages, "CVEdetails filter page") 
					@custom_filter 			= find_by_title(@site.pages, "Custom filter page") 
        		end

        		# Site config
        		specify "should have correct site config" do
	        		case @type
	        		when "default"
	        			expect(@site.config["jekyll-secinfo"]).to eq({})
		        	when "mitre"
	        			expect(@site.config["jekyll-secinfo"]).to eq({"cve"=>{"style"=>"mitre"}})
		        	when "weird"
	        			expect(@site.config["jekyll-secinfo"]).to eq({"cve"=>{"style"=>"feiuyvineueaiuse"}})
		        	when "nvd"
	        			expect(@site.config["jekyll-secinfo"]).to eq({"cve"=>{"style"=>"nvd"}})
		        	when "cvedetails"
	        			expect(@site.config["jekyll-secinfo"]).to eq({"cve"=>{"style"=>"cvedetails"}})
		        	when "custom"
	        			expect(@site.config["jekyll-secinfo"]).to eq({"cve"=>{"url"=>"https://localhost/%s/info.html"}})
	        		else
	        			raise "config type '#{@type}' unexpected"
		        	end
		        end


		        describe "index page" do

			        specify "config should merge correctly" do
		        		case @type
		        		when "default"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq({"cve"=>{"url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        	when "mitre"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq({"cve"=>{"style"=>"mitre","url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        	when "weird"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq({"cve"=>{"style"=>"feiuyvineueaiuse", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        	when "nvd"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq({"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"}})
			        	when "cvedetails"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq({"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"}})
			        	when "custom"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq({"cve"=>{"url"=>"https://localhost/%s/info.html"}})
		        		else
		        			raise "config type '#{@type}' unexpected"
			        	end
			        end
	
	        		it "all {\% cve tags should be gone" do
					    expect(@index_page.output).not_to include("{\% cve")
					    expect(@index_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
					    expect(@index_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
					    expect(@index_page.output).not_to include('number {% cve: 2021-00003 %} number')
					    expect(@index_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
					end

					it "all {\% cve tags should be replaced" do
		        		case @type
		        		when "default", "mitre", "weird"
							expect(@index_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
							expect(@index_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
							expect(@index_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
							expect(@index_page.output).to include('invalid cve-invalid  invalid')
			        	when "nvd"
							expect(@index_page.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
							expect(@index_page.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
							expect(@index_page.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
							expect(@index_page.output).to include('invalid cve-invalid  invalid')
			        	when "cvedetails"
							expect(@index_page.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve">CVE-2020-8200</a> full')
							expect(@index_page.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve">CVE-2018-20808</a> lower')
							expect(@index_page.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve">CVE-2000-1206</a> number')
							expect(@index_page.output).to include('invalid cve-invalid  invalid')
			        	when "custom"
							expect(@index_page.output).to include('full <a href="https://localhost/2020-8200/info.html" class="cve">CVE-2020-8200</a> full')
							expect(@index_page.output).to include('lower <a href="https://localhost/2018-20808/info.html" class="cve">CVE-2018-20808</a> lower')
							expect(@index_page.output).to include('number <a href="https://localhost/2000-1206/info.html" class="cve">CVE-2000-1206</a> number')
							expect(@index_page.output).to include('invalid cve-invalid  invalid')
		        		else
		        			raise "config type '#{@type}' unexpected"
			        	end
					end
			    end

			    describe "mitre page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@mitre_page.data)).to eq({"cve"=>{"style"=>"mitre", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        end

			    	specify "all {\% cve tags should be gone" do
						expect(@mitre_page.output).not_to include("{\% cve")
						expect(@mitre_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
						expect(@mitre_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
						expect(@mitre_page.output).not_to include('number {% cve: 2021-00003 %} number')
						expect(@mitre_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
					end

					it "all {\% cve tags should be replaced" do
						expect(@mitre_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
						expect(@mitre_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
						expect(@mitre_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
						expect(@mitre_page.output).to include('invalid cve-invalid  invalid')
					end

				end #mitre page

				describe "weird page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@weird_page.data)).to eq({"cve"=>{"style"=>"supercalifragicexpialidocious", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        end

			    	specify "all {\% cve tags should be gone" do
						expect(@weird_page.output).not_to include("{\% cve")
						expect(@weird_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
						expect(@weird_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
						expect(@weird_page.output).not_to include('number {% cve: 2021-00003 %} number')
						expect(@weird_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
					end

					specify "all {\% cve tags should be replaced" do
						expect(@weird_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
						expect(@weird_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
						expect(@weird_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
						expect(@weird_page.output).to include('invalid cve-invalid  invalid')
					end
				end #weird page

				describe "nvd page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@nvd_page.data)).to eq({"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"}})
			        end

			    	specify "all {\% cve tags should be gone" do
						expect(@nvd_page.output).not_to include("{\% cve")
						expect(@nvd_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
						expect(@nvd_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
						expect(@nvd_page.output).not_to include('number {% cve: 2021-00003 %} number')
						expect(@nvd_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
					end

					specify "all {\% cve tags should be replaced" do
						expect(@nvd_page.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
						expect(@nvd_page.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
						expect(@nvd_page.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
						expect(@nvd_page.output).to include('invalid cve-invalid  invalid')
					end
				end

				describe "cvedetails page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@cvedetails_page.data)).to eq({"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"}})
			        end

					specify "all {\% cve tags should be gone" do
						expect(@cvedetails_page.output).not_to include("{\% cve")
						expect(@cvedetails_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
						expect(@cvedetails_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
						expect(@cvedetails_page.output).not_to include('number {% cve: 2021-00003 %} number')
						expect(@cvedetails_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
					end

					specify "all {\% cve tags should be replaced" do
						expect(@cvedetails_page.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve">CVE-2020-8200</a> full')
						expect(@cvedetails_page.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve">CVE-2018-20808</a> lower')
						expect(@cvedetails_page.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve">CVE-2000-1206</a> number')
						expect(@cvedetails_page.output).to include('invalid cve-invalid  invalid')
					end
				end # cvedetails

				describe "custom page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@custom_page.data)).to eq({"cve"=>{"url"=>"https://localhost/%s/details"}})
			        end

					specify "all {\% cve tags should be gone" do
						expect(@custom_page.output).not_to include("{\% cve")
						expect(@custom_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
						expect(@custom_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
						expect(@custom_page.output).not_to include('number {% cve: 2021-00003 %} number')
						expect(@custom_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
					end

					specify "all {\% cve tags should be replaced" do
						expect(@custom_page.output).to include('full <a href="https://localhost/2020-8200/details" class="cve">CVE-2020-8200</a> full')
						expect(@custom_page.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve">CVE-2018-20808</a> lower')
						expect(@custom_page.output).to include('number <a href="https://localhost/2000-1206/details" class="cve">CVE-2000-1206</a> number')
						expect(@custom_page.output).to include('invalid cve-invalid  invalid')
					end
				end #custom

				#
				# Filters
				#
				describe "default filter" do
			        specify "config should merge correctly" do
		        		case @type
		        		when "default"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq({"cve"=>{"url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        	when "mitre"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq({"cve"=>{"style"=>"mitre", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        	when "weird"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq({"cve"=>{"style"=>"feiuyvineueaiuse", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        	when "nvd"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq( {"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"}})
			        	when "cvedetails"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq({"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"}})
			        	when "custom"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq({"cve"=>{"url"=>"https://localhost/%s/info.html"}})
		        		else
		        			raise "config type '#{@type}' unexpected"
			        	end
			        end

					specify "all cve filters should be gone" do
						expect(@default_filter.output).not_to include("cve }}")
						expect(@default_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
						expect(@default_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
						expect(@default_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
						expect(@default_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
					end

					specify "all {{ tags should be replaced" do
		        		case @type
		        		when "default", "mitre", "weird"
							expect(@default_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
							expect(@default_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
							expect(@default_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
			        	when "nvd"
							expect(@default_filter.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
							expect(@default_filter.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
							expect(@default_filter.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
			        	when "cvedetails"
							expect(@default_filter.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve">CVE-2020-8200</a> full')
							expect(@default_filter.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve">CVE-2018-20808</a> lower')
							expect(@default_filter.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve">CVE-2000-1206</a> number')
			        	when "custom"
							expect(@default_filter.output).to include('full <a href="https://localhost/2020-8200/info.html" class="cve">CVE-2020-8200</a> full')
							expect(@default_filter.output).to include('lower <a href="https://localhost/2018-20808/info.html" class="cve">CVE-2018-20808</a> lower')
							expect(@default_filter.output).to include('number <a href="https://localhost/2000-1206/info.html" class="cve">CVE-2000-1206</a> number')
		        		else
		        			raise "config type '#{@type}' unexpected"
			        	end
						expect(@default_filter.output).to include('invalid cve-invalid invalid')
					end

				end # default filter

				describe "mitre filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@mitre_filter.data)).to eq({"cve"=>{"style"=>"mitre","url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        end

			        specify "all cve filter tages should be gone" do
						expect(@mitre_filter.output).not_to include("cve }}")
						expect(@mitre_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
						expect(@mitre_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
						expect(@mitre_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
						expect(@mitre_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
					end

					specify "all {{ tags should be replaced" do
						expect(@mitre_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
						expect(@mitre_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
						expect(@mitre_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
						expect(@mitre_filter.output).to include('invalid cve-invalid invalid')
					end
				end #mitre

				describe "weird filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@weird_filter.data)).to eq({"cve"=>{"style"=>"supercalifragicexpialidocious", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}})
			        end

			        specify "all cve filter tages should be gone" do
						expect(@weird_filter.output).not_to include("cve }}")
						expect(@weird_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
						expect(@weird_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
						expect(@weird_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
						expect(@weird_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
					end

					specify "all {{ tags should be replaced" do
						expect(@weird_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
						expect(@weird_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
						expect(@weird_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
						expect(@weird_filter.output).to include('invalid cve-invalid invalid')
					end
				end #weird

				describe "nvd filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@nvd_filter.data)).to eq({"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"}})
			        end

			        specify "all cve filter tages should be gone" do
						expect(@nvd_filter.output).not_to include("cve }}")
						expect(@nvd_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
						expect(@nvd_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
						expect(@nvd_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
						expect(@nvd_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
					end

  
					specify "all {{ tags should be replaced" do
						expect(@nvd_filter.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
						expect(@nvd_filter.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
						expect(@nvd_filter.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
						expect(@nvd_filter.output).to include('invalid cve-invalid invalid')
					end
				end #nvd

				describe "cvedetails filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@cvedetails_filter.data)).to eq({"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"}})
			        end

			        specify "all cve filter tages should be gone" do
						expect(@cvedetails_filter.output).not_to include("cve }}")
						expect(@cvedetails_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
						expect(@cvedetails_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
						expect(@cvedetails_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
						expect(@cvedetails_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
					end

					specify "all {{ tags should be replaced" do
						expect(@cvedetails_filter.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve">CVE-2020-8200</a> full')
						expect(@cvedetails_filter.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve">CVE-2018-20808</a> lower')
						expect(@cvedetails_filter.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve">CVE-2000-1206</a> number')
						expect(@cvedetails_filter.output).to include('invalid cve-invalid invalid')
					end
				end #cvedetails

				describe "custom filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@custom_filter.data)).to eq({"cve"=>{"url"=>"https://localhost/%s/details"}})
			        end

			        specify "all cve filter tages should be gone" do
						expect(@custom_filter.output).not_to include("cve }}")
						expect(@custom_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
						expect(@custom_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
						expect(@custom_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
						expect(@custom_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
					end

					specify "all {{ tags should be replaced" do
						expect(@custom_filter.output).to include('full <a href="https://localhost/2020-8200/details" class="cve">CVE-2020-8200</a> full')
						expect(@custom_filter.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve">CVE-2018-20808</a> lower')
						expect(@custom_filter.output).to include('number <a href="https://localhost/2000-1206/details" class="cve">CVE-2000-1206</a> number')
						expect(@custom_filter.output).to include('invalid cve-invalid invalid')
					end
				end #custom

        	end #type
      	end #end site
    end 
  
end

