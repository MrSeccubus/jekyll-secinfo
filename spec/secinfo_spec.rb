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
	      							},
	      							"cwe" => {
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
	      							},
	      							"cwe" => {
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
	      							},
	      							"cwe" => {
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
	      							},
	      							"cwe" => {
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
	      							},
	      							"cwe" => {
	      								"url" => "https://localhost/%s/info.html"
	      							},
	      							"divd" => {
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
	        			expect(@site.config["jekyll-secinfo"]).to eq(
	        				{
	        					"cve"=>{"style"=>"mitre"}, 
	        					"cwe"=>{"style"=>"mitre"}
	        				}
	        			)
		        	when "weird"
	        			expect(@site.config["jekyll-secinfo"]).to eq(
	        				{
	        					"cve"=>{"style"=>"feiuyvineueaiuse"}, 
	        					"cwe"=>{"style"=>"feiuyvineueaiuse"}
	        				}
	        			)
		        	when "nvd"
	        			expect(@site.config["jekyll-secinfo"]).to eq(
	        				{
	        					"cve"=>{"style"=>"nvd"},
	        					"cwe"=>{"style"=>"nvd"},
	        				}
	        			)
		        	when "cvedetails"
	        			expect(@site.config["jekyll-secinfo"]).to eq(
	        				{
	        					"cve"=>{"style"=>"cvedetails"}, 
	        					"cwe"=>{"style"=>"cvedetails"}
	        				}
	        			)
		        	when "custom"
	        			expect(@site.config["jekyll-secinfo"]).to eq(
	        				{
	        					"cve"=>{"url"=>"https://localhost/%s/info.html"}, 
	        					"cwe"=>{"url"=>"https://localhost/%s/info.html"},
	        					"divd" => {"url"=>"https://localhost/%s/info.html"}
	        				}
	        			)
	        		else
	        			raise "config type '#{@type}' unexpected"
		        	end
		        end


		        describe "index page" do

			        specify "config should merge correctly" do
		        		case @type
		        		when "default"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq(
				        		{
				        			"cve"=>{"url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}, 
				        			"cwe"=>{"url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "mitre"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"mitre", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}, 
				        			"cwe"=>{"style"=>"mitre", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "weird"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"feiuyvineueaiuse", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}, 
				        			"cwe"=>{"style"=>"feiuyvineueaiuse", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "nvd"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"}, 
				        			"cwe"=>{"style"=>"nvd", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}	
				        	)
			        	when "cvedetails"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"}, 
				        			"cwe"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cwe-details/"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "custom"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@index_page.data)).to eq(
				        		{
				        			"cve"=>{"url"=>"https://localhost/%s/info.html"}, 
				        			"cwe"=>{"url"=>"https://localhost/%s/info.html"},
				        			"divd" => {"url"=>"https://localhost/%s/info.html"}
				        		}
				        	)
		        		else
		        			raise "config type '#{@type}' unexpected"
			        	end
			        end
	
	        		describe "cve" do
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
								expect(@index_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@index_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@index_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
								expect(@index_page.output).to include('invalid cve-invalid  invalid')
				        	when "nvd"
								expect(@index_page.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@index_page.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@index_page.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
								expect(@index_page.output).to include('invalid cve-invalid  invalid')
				        	when "cvedetails"
								expect(@index_page.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@index_page.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@index_page.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve secinfo">CVE-2000-1206</a> number')
								expect(@index_page.output).to include('invalid cve-invalid  invalid')
				        	when "custom"
								expect(@index_page.output).to include('full <a href="https://localhost/2020-8200/info.html" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@index_page.output).to include('lower <a href="https://localhost/2018-20808/info.html" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@index_page.output).to include('number <a href="https://localhost/2000-1206/info.html" class="cve secinfo">CVE-2000-1206</a> number')
								expect(@index_page.output).to include('invalid cve-invalid  invalid')
			        		else
			        			raise "config type '#{@type}' unexpected"
				        	end
				        end 
				    end #cve

	        		describe "cwe" do
	        			it "all {\% cwe tags should be gone" do
						    expect(@index_page.output).not_to include("{\% cwe")
							expect(@index_page.output).not_to include('full {% cwe CWE-79 %} full')
							expect(@index_page.output).not_to include('lower {% cve cwe-787 %} lower')
							expect(@index_page.output).not_to include('number {% cwe 20} number')
							expect(@index_page.output).not_to include('invalid {% cwe cwe-invalid %} invalid')
						end
					

						it "all {\% cwe tags should be replaced" do
			        		case @type
			        		when "default", "mitre", "weird", "nvd"
								expect(@index_page.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
								expect(@index_page.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
								expect(@index_page.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
								expect(@index_page.output).to include('invalid cwe-invalid  invalid')
				        	when "cvedetails"
								expect(@index_page.output).to include('full <a href="https://www.cvedetails.com/cwe-details/79" class="cwe secinfo">CWE-79</a> full')
								expect(@index_page.output).to include('lower <a href="https://www.cvedetails.com/cwe-details/787" class="cwe secinfo">CWE-787</a> lower')
								expect(@index_page.output).to include('number <a href="https://www.cvedetails.com/cwe-details/20" class="cwe secinfo">CWE-20</a> number')
								expect(@index_page.output).to include('invalid cwe-invalid  invalid')
				        	when "custom"
								expect(@index_page.output).to include('full <a href="https://localhost/79/info.html" class="cwe secinfo">CWE-79</a> full')
								expect(@index_page.output).to include('lower <a href="https://localhost/787/info.html" class="cwe secinfo">CWE-787</a> lower')
								expect(@index_page.output).to include('number <a href="https://localhost/20/info.html" class="cwe secinfo">CWE-20</a> number')
								expect(@index_page.output).to include('invalid cwe-invalid  invalid')
			        		else
			        			raise "config type '#{@type}' unexpected"
				        	end
				        end 
				    end # cwe

	        		describe "divd" do
	        			it "all {\% cwe tags should be gone" do
						    expect(@index_page.output).not_to include("{\% divd")
							expect(@index_page.output).not_to include('full {% divd DIVD-2020-00001 %} full')
							expect(@index_page.output).not_to include('lower {% divd divd-2020-00002 %} lower')
							expect(@index_page.output).not_to include('number {% divd 2020-00003 %} number')
							expect(@index_page.output).not_to include('invalid {% divd divd-invalid %} invalid')
						end
					

						it "all {\% cwe tags should be replaced" do
			        		case @type
			        		when "default", "mitre", "weird", "nvd", "cvedetails"
								expect(@index_page.output).to include('full <a href="https://csirt.divd.nl/DIVD-2020-00001" class="divd secinfo">DIVD-2020-00001</a> full')
								expect(@index_page.output).to include('lower <a href="https://csirt.divd.nl/DIVD-2020-00002" class="divd secinfo">DIVD-2020-00002</a> lower')
								expect(@index_page.output).to include('number <a href="https://csirt.divd.nl/DIVD-2020-00003" class="divd secinfo">DIVD-2020-00003</a> number')
								expect(@index_page.output).to include('invalid divd-invalid  invalid')
				        	when "custom"
								expect(@index_page.output).to include('full <a href="https://localhost/2020-00001/info.html" class="divd secinfo">DIVD-2020-00001</a> full')
								expect(@index_page.output).to include('lower <a href="https://localhost/2020-00002/info.html" class="divd secinfo">DIVD-2020-00002</a> lower')
								expect(@index_page.output).to include('number <a href="https://localhost/2020-00003/info.html" class="divd secinfo">DIVD-2020-00003</a> number')
								expect(@index_page.output).to include('invalid divd-invalid  invalid')
			        		else
			        			raise "config type '#{@type}' unexpected"
				        	end
				        end 
				    end # cwe
			    end #index page

			    describe "mitre page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@mitre_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"mitre", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"}, 
				        			"cwe"=>{"style"=>"mitre", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        end

			        describe "cve" do
				    	specify "all {\% cve tags should be gone" do
							expect(@mitre_page.output).not_to include("{\% cve")
							expect(@mitre_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
							expect(@mitre_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
							expect(@mitre_page.output).not_to include('number {% cve: 2021-00003 %} number')
							expect(@mitre_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
						end

						it "all {\% cve tags should be replaced" do
							expect(@mitre_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@mitre_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@mitre_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@mitre_page.output).to include('invalid cve-invalid  invalid')
						end
					end #cve
					
			        describe "cwe" do
				    	specify "all {\% cwe tags should be gone" do
						    expect(@mitre_page.output).not_to include("{\% cwe")
							expect(@mitre_page.output).not_to include('full {% cwe CWE-79 %} full')
							expect(@mitre_page.output).not_to include('lower {% cve cwe-787 %} lower')
							expect(@mitre_page.output).not_to include('number {% cwe 20} number')
							expect(@mitre_page.output).not_to include('invalid {% cwe cwe-invalid %} invalid')
						end

						it "all {\% cwe tags should be replaced" do
							expect(@mitre_page.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
							expect(@mitre_page.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
							expect(@mitre_page.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
							expect(@mitre_page.output).to include('invalid cwe-invalid  invalid')
						end
					end #cwe
					
				end #mitre page

				describe "weird page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@weird_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"supercalifragicexpialidocious", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"},
				        			"cwe"=>{"style"=>"supercalifragicexpialidocious", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        end

			    	describe "cve tags" do
				    	specify "are all gone" do
							expect(@weird_page.output).not_to include("{\% cve")
							expect(@weird_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
							expect(@weird_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
							expect(@weird_page.output).not_to include('number {% cve: 2021-00003 %} number')
							expect(@weird_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
						end

						specify "are all correctly rendered" do
							expect(@weird_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@weird_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@weird_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@weird_page.output).to include('invalid cve-invalid  invalid')
						end
					end

					describe "cwe tags" do
				    	specify "are all gone" do
						    expect(@weird_page.output).not_to include("{\% cwe")
							expect(@weird_page.output).not_to include('full {% cwe CWE-79 %} full')
							expect(@weird_page.output).not_to include('lower {% cve cwe-787 %} lower')
							expect(@weird_page.output).not_to include('number {% cwe 20} number')
							expect(@weird_page.output).not_to include('invalid {% cwe cwe-invalid %} invalid')
						end

						specify "are all correctly rendered" do
							expect(@weird_page.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
							expect(@weird_page.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
							expect(@weird_page.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
							expect(@weird_page.output).to include('invalid cwe-invalid  invalid')
						end
					end #cwe

				end #weird page

				describe "nvd page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@nvd_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"}, 
				        			"cwe"=>{"style"=>"nvd", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        end

			    	describe "cve tags" do
				    	specify "should be gone" do
							expect(@nvd_page.output).not_to include("{\% cve")
							expect(@nvd_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
							expect(@nvd_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
							expect(@nvd_page.output).not_to include('number {% cve: 2021-00003 %} number')
							expect(@nvd_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@nvd_page.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@nvd_page.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@nvd_page.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@nvd_page.output).to include('invalid cve-invalid  invalid')
						end
					end #cve

					describe "cwe tags" do
				    	specify "are all gone" do
						    expect(@nvd_page.output).not_to include("{\% cwe")
							expect(@nvd_page.output).not_to include('full {% cwe CWE-79 %} full')
							expect(@nvd_page.output).not_to include('lower {% cve cwe-787 %} lower')
							expect(@nvd_page.output).not_to include('number {% cwe 20} number')
							expect(@nvd_page.output).not_to include('invalid {% cwe cwe-invalid %} invalid')
						end

						specify "are all correctly rendered" do
							expect(@nvd_page.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
							expect(@nvd_page.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
							expect(@nvd_page.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
							expect(@nvd_page.output).to include('invalid cwe-invalid  invalid')
						end
					end #cwe


				end

				describe "cvedetails page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@cvedetails_page.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"},
				        			"cwe" => {"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cwe-details/"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        end

			        describe "cve tags" do
						specify "are all be gone" do
							expect(@cvedetails_page.output).not_to include("{\% cve")
							expect(@cvedetails_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
							expect(@cvedetails_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
							expect(@cvedetails_page.output).not_to include('number {% cve: 2021-00003 %} number')
							expect(@cvedetails_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
						end

						specify "all rendered correctly" do
							expect(@cvedetails_page.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@cvedetails_page.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@cvedetails_page.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@cvedetails_page.output).to include('invalid cve-invalid  invalid')
						end
					end #cve

					describe "cwe tags" do
				    	specify "are all gone" do
						    expect(@cvedetails_page.output).not_to include("{\% cwe")
							expect(@cvedetails_page.output).not_to include('full {% cwe CWE-79 %} full')
							expect(@cvedetails_page.output).not_to include('lower {% cve cwe-787 %} lower')
							expect(@cvedetails_page.output).not_to include('number {% cwe 20} number')
							expect(@cvedetails_page.output).not_to include('invalid {% cwe cwe-invalid %} invalid')
						end

						specify "are all correctly rendered" do
							expect(@cvedetails_page.output).to include('full <a href="https://www.cvedetails.com/cwe-details/79" class="cwe secinfo">CWE-79</a> full')
							expect(@cvedetails_page.output).to include('lower <a href="https://www.cvedetails.com/cwe-details/787" class="cwe secinfo">CWE-787</a> lower')
							expect(@cvedetails_page.output).to include('number <a href="https://www.cvedetails.com/cwe-details/20" class="cwe secinfo">CWE-20</a> number')
							expect(@cvedetails_page.output).to include('invalid cwe-invalid  invalid')
						end
					end #cwe

				end # cvedetails

				describe "custom page" do
			        specify "config should merge correctly" do
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@custom_page.data)).to eq(
				        		{
				        			"cve"=>{"url"=>"https://localhost/%s/details"},
				        			"cwe" => {"url"=>"https://localhost/%s/details"},
									"divd" => {"url"=>"https://localhost/%s/details"}				        		}
				        	)
			        end

					describe "cve tags" do
						specify "should all be gone" do
							expect(@custom_page.output).not_to include("{\% cve")
							expect(@custom_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
							expect(@custom_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
							expect(@custom_page.output).not_to include('number {% cve: 2021-00003 %} number')
							expect(@custom_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@custom_page.output).to include('full <a href="https://localhost/2020-8200/details" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@custom_page.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@custom_page.output).to include('number <a href="https://localhost/2000-1206/details" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@custom_page.output).to include('invalid cve-invalid  invalid')
						end
					end #cve 

					describe "cwe tags" do
				    	specify "are all gone" do
						    expect(@custom_page.output).not_to include("{\% cwe")
							expect(@custom_page.output).not_to include('full {% cwe CWE-79 %} full')
							expect(@custom_page.output).not_to include('lower {% cve cwe-787 %} lower')
							expect(@custom_page.output).not_to include('number {% cwe 20} number')
							expect(@custom_page.output).not_to include('invalid {% cwe cwe-invalid %} invalid')
						end

						specify "are all correctly rendered" do
							expect(@custom_page.output).to include('full <a href="https://localhost/79/details" class="cwe secinfo">CWE-79</a> full')
							expect(@custom_page.output).to include('lower <a href="https://localhost/787/details" class="cwe secinfo">CWE-787</a> lower')
							expect(@custom_page.output).to include('number <a href="https://localhost/20/details" class="cwe secinfo">CWE-20</a> number')
							expect(@custom_page.output).to include('invalid cwe-invalid  invalid')
						end
					end #cwe

	        		describe "divd" do
				    	specify "are all gone" do
						    expect(@custom_page.output).not_to include("{\% divd")
							expect(@custom_page.output).not_to include('full {% divd DIVD-2020-00001 %} full')
							expect(@custom_page.output).not_to include('lower {% divd divd-2020-00002 %} lower')
							expect(@custom_page.output).not_to include('number {% divd 2020-00003 %} number')
							expect(@custom_page.output).not_to include('invalid {% divd divd-invalid %} invalid')
						end
					
						specify "are all correctly rendered" do
							expect(@custom_page.output).to include('full <a href="https://localhost/2020-00001/details" class="divd secinfo">DIVD-2020-00001</a> full')
							expect(@custom_page.output).to include('lower <a href="https://localhost/2020-00002/details" class="divd secinfo">DIVD-2020-00002</a> lower')
							expect(@custom_page.output).to include('number <a href="https://localhost/2020-00003/details" class="divd secinfo">DIVD-2020-00003</a> number')
							expect(@custom_page.output).to include('invalid divd-invalid  invalid')
				        end 
				    end #divd
				end #custom

				#
				# Filters
				#
				describe "default filter" do
			        specify "config should merge correctly" do
		        		case @type
		        		when "default"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq(
				        		{
				        			"cve"=>{"url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"},
				        			"cwe"=>{"url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "mitre"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"mitre", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"},
				        			"cwe"=>{"style"=>"mitre", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "weird"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"feiuyvineueaiuse", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"},
				        			"cwe"=>{"style"=>"feiuyvineueaiuse", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "nvd"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"},
				        			"cwe"=>{"style"=>"nvd", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "cvedetails"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq(
				        		{
				        			"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"},
				        			"cwe"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cwe-details/"},
				        			"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
				        		}
				        	)
			        	when "custom"
				        	expect(Jekyll::Secinfo::Config.get(@site.config,@default_filter.data)).to eq(
				        		{
				        			"cve"=>{"url"=>"https://localhost/%s/info.html"},
				        			"cwe"=>{"url"=>"https://localhost/%s/info.html"},
				        			"divd" => {"url"=>"https://localhost/%s/info.html"}
				        		}
				        	)
		        		else
		        			raise "config type '#{@type}' unexpected"
			        	end
			        end

					describe "cve filters" do
						specify "should all be gone" do
							expect(@default_filter.output).not_to include("cve }}")
							expect(@default_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
							expect(@default_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
							expect(@default_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
							expect(@default_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
						end

						specify "should all be rendered correctly" do
			        		case @type
			        		when "default", "mitre", "weird"
								expect(@default_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@default_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@default_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
				        	when "nvd"
								expect(@default_filter.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@default_filter.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@default_filter.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
				        	when "cvedetails"
								expect(@default_filter.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@default_filter.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@default_filter.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve secinfo">CVE-2000-1206</a> number')
				        	when "custom"
								expect(@default_filter.output).to include('full <a href="https://localhost/2020-8200/info.html" class="cve secinfo">CVE-2020-8200</a> full')
								expect(@default_filter.output).to include('lower <a href="https://localhost/2018-20808/info.html" class="cve secinfo">CVE-2018-20808</a> lower')
								expect(@default_filter.output).to include('number <a href="https://localhost/2000-1206/info.html" class="cve secinfo">CVE-2000-1206</a> number')
			        		else
			        			raise "config type '#{@type}' unexpected"
				        	end
							expect(@default_filter.output).to include('invalid cve-invalid invalid')
						end
					end # cve

					describe "cwe filters" do
						specify "should all be gone" do
							expect(@default_filter.output).not_to include("cwe }}")
							expect(@default_filter.output).not_to include('full {% "CWE-79" | cwe %} full')
							expect(@default_filter.output).not_to include('lower {% "cwe-787" | cwe %} lower')
							expect(@default_filter.output).not_to include('number {% "20" | cwe %} number')
							expect(@default_filter.output).not_to include('invalid {% "cwe-invalid" | cwe %} invalid')
						end

						specify "should all be rendered correctly" do
			        		case @type
			        		when "default", "mitre", "weird", "nvd"
								expect(@default_filter.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
								expect(@default_filter.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
								expect(@default_filter.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
				        	when "cvedetails"
								expect(@default_filter.output).to include('full <a href="https://www.cvedetails.com/cwe-details/79" class="cwe secinfo">CWE-79</a> full')
								expect(@default_filter.output).to include('lower <a href="https://www.cvedetails.com/cwe-details/787" class="cwe secinfo">CWE-787</a> lower')
								expect(@default_filter.output).to include('number <a href="https://www.cvedetails.com/cwe-details/20" class="cwe secinfo">CWE-20</a> number')
				        	when "custom"
								expect(@default_filter.output).to include('full <a href="https://localhost/79/info.html" class="cwe secinfo">CWE-79</a> full')
								expect(@default_filter.output).to include('lower <a href="https://localhost/787/info.html" class="cwe secinfo">CWE-787</a> lower')
								expect(@default_filter.output).to include('number <a href="https://localhost/20/info.html" class="cwe secinfo">CWE-20</a> number')
			        		else
			        			raise "config type '#{@type}' unexpected"
				        	end
							expect(@default_filter.output).to include('invalid cwe-invalid invalid')
						end
					end #cwe 

	        		describe "divd" do
				    	specify "are all gone" do
						    expect(@default_filter.output).not_to include("{\% divd")
							expect(@default_filter.output).not_to include('full {% divd DIVD-2020-00001 %} full')
							expect(@default_filter.output).not_to include('lower {% divd divd-2020-00002 %} lower')
							expect(@default_filter.output).not_to include('number {% divd 2020-00003 %} number')
							expect(@default_filter.output).not_to include('invalid {% divd divd-invalid %} invalid')
						end
					
						specify "are all correctly rendered" do
			        		case @type
			        		when "default", "mitre", "weird", "nvd", "cvedetails"
								expect(@default_filter.output).to include('full <a href="https://csirt.divd.nl/DIVD-2020-00001" class="divd secinfo">DIVD-2020-00001</a> full')
								expect(@default_filter.output).to include('lower <a href="https://csirt.divd.nl/DIVD-2020-00002" class="divd secinfo">DIVD-2020-00002</a> lower')
								expect(@default_filter.output).to include('number <a href="https://csirt.divd.nl/DIVD-2020-00003" class="divd secinfo">DIVD-2020-00003</a> number')
				        	when "custom"
								expect(@default_filter.output).to include('full <a href="https://localhost/2020-00001/info.html" class="divd secinfo">DIVD-2020-00001</a> full')
								expect(@default_filter.output).to include('lower <a href="https://localhost/2020-00002/info.html" class="divd secinfo">DIVD-2020-00002</a> lower')
								expect(@default_filter.output).to include('number <a href="https://localhost/2020-00003/info.html" class="divd secinfo">DIVD-2020-00003</a> number')
			        		else
			        			raise "config type '#{@type}' unexpected"
				        	end
							expect(@default_filter.output).to include('invalid divd-invalid  invalid')
				        end 
				    end #divd

				end # default filter

				describe "mitre filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@mitre_filter.data)).to eq(
			        		{
			        			"cve"=>{"style"=>"mitre","url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"},
			        			"cwe"=>{"style"=>"mitre", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        		"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
			        		}
			        	)
			        end

					describe "cve filters" do
						specify "should all be gone" do
							expect(@mitre_filter.output).not_to include("cve }}")
							expect(@mitre_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
							expect(@mitre_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
							expect(@mitre_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
							expect(@mitre_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@mitre_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@mitre_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@mitre_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@mitre_filter.output).to include('invalid cve-invalid invalid')
						end
					end #cve

					describe "cwe filters" do
						specify "should all be gone" do
							expect(@mitre_filter.output).not_to include("cwe }}")
							expect(@mitre_filter.output).not_to include('full {% "CWE-79" | cwe %} full')
							expect(@mitre_filter.output).not_to include('lower {% "cwe-787" | cwe %} lower')
							expect(@mitre_filter.output).not_to include('number {% "20" | cwe %} number')
							expect(@mitre_filter.output).not_to include('invalid {% "cwe-invalid" | cwe %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@mitre_filter.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
							expect(@mitre_filter.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
							expect(@mitre_filter.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
							expect(@mitre_filter.output).to include('invalid cwe-invalid invalid')
						end
					end #cwe 
				end #mitre

				describe "weird filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@weird_filter.data)).to eq(
			        		{
			        			"cve"=>{"style"=>"supercalifragicexpialidocious", "url"=>"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-"},
			        			"cwe"=>{"style"=>"supercalifragicexpialidocious", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        		"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
			        		}
			        	)
			        end

					describe "cve filters" do
						specify "should all be gone" do
							expect(@weird_filter.output).not_to include("cve }}")
							expect(@weird_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
							expect(@weird_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
							expect(@weird_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
							expect(@weird_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@weird_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@weird_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@weird_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@weird_filter.output).to include('invalid cve-invalid invalid')
						end
					end #cve

					describe "cwe filters" do
						specify "should all be gone" do
							expect(@weird_filter.output).not_to include("cwe }}")
							expect(@weird_filter.output).not_to include('full {% "CWE-79" | cwe %} full')
							expect(@weird_filter.output).not_to include('lower {% "cwe-787" | cwe %} lower')
							expect(@weird_filter.output).not_to include('number {% "20" | cwe %} number')
							expect(@weird_filter.output).not_to include('invalid {% "cwe-invalid" | cwe %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@weird_filter.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
							expect(@weird_filter.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
							expect(@weird_filter.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
							expect(@weird_filter.output).to include('invalid cwe-invalid invalid')
						end
					end #cwe 
				end #weird

				describe "nvd filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@nvd_filter.data)).to eq(
			        		{
			        			"cve"=>{"style"=>"nvd", "url"=>"https://nvd.nist.gov/vuln/detail/CVE-"},
			        			"cwe"=>{"style"=>"nvd", "url"=>"https://cwe.mitre.org/data/definitions/%s.html"},
				        		"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
			        		}
			        	)
			        end

					describe "cve filters" do
						specify "should all be gone" do
							expect(@nvd_filter.output).not_to include("cve }}")
							expect(@nvd_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
							expect(@nvd_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
							expect(@nvd_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
							expect(@nvd_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
						end

	  
						specify "should all be rendered correctly" do
							expect(@nvd_filter.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@nvd_filter.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@nvd_filter.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@nvd_filter.output).to include('invalid cve-invalid invalid')
						end
					end # cve

					describe "cwe filters" do
						specify "should all be gone" do
							expect(@nvd_filter.output).not_to include("cwe }}")
							expect(@nvd_filter.output).not_to include('full {% "CWE-79" | cwe %} full')
							expect(@nvd_filter.output).not_to include('lower {% "cwe-787" | cwe %} lower')
							expect(@nvd_filter.output).not_to include('number {% "20" | cwe %} number')
							expect(@nvd_filter.output).not_to include('invalid {% "cwe-invalid" | cwe %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@nvd_filter.output).to include('full <a href="https://cwe.mitre.org/data/definitions/79.html" class="cwe secinfo">CWE-79</a> full')
							expect(@nvd_filter.output).to include('lower <a href="https://cwe.mitre.org/data/definitions/787.html" class="cwe secinfo">CWE-787</a> lower')
							expect(@nvd_filter.output).to include('number <a href="https://cwe.mitre.org/data/definitions/20.html" class="cwe secinfo">CWE-20</a> number')
							expect(@nvd_filter.output).to include('invalid cwe-invalid invalid')
						end
					end #cwe 
				end #nvd

				describe "cvedetails filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@cvedetails_filter.data)).to eq(
			        		{
		        				"cve"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cve/CVE-%s/"}, 
		        				"cwe"=>{"style"=>"cvedetails", "url"=>"https://www.cvedetails.com/cwe-details/"},
				        		"divd" => {"url"=>"https://csirt.divd.nl/DIVD-"}
			        		}
		        		)
			        end

					describe "cve filters" do
						specify "should all be gone" do
							expect(@cvedetails_filter.output).not_to include("cve }}")
							expect(@cvedetails_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
							expect(@cvedetails_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
							expect(@cvedetails_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
							expect(@cvedetails_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@cvedetails_filter.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@cvedetails_filter.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@cvedetails_filter.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@cvedetails_filter.output).to include('invalid cve-invalid invalid')
						end
					end #cve

					describe "cwe filters" do
						specify "should all be gone" do
							expect(@cvedetails_filter.output).not_to include("cwe }}")
							expect(@cvedetails_filter.output).not_to include('full {% "CWE-79" | cwe %} full')
							expect(@cvedetails_filter.output).not_to include('lower {% "cwe-787" | cwe %} lower')
							expect(@cvedetails_filter.output).not_to include('number {% "20" | cwe %} number')
							expect(@cvedetails_filter.output).not_to include('invalid {% "cwe-invalid" | cwe %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@cvedetails_filter.output).to include('full <a href="https://www.cvedetails.com/cwe-details/79" class="cwe secinfo">CWE-79</a> full')
							expect(@cvedetails_filter.output).to include('lower <a href="https://www.cvedetails.com/cwe-details/787" class="cwe secinfo">CWE-787</a> lower')
							expect(@cvedetails_filter.output).to include('number <a href="https://www.cvedetails.com/cwe-details/20" class="cwe secinfo">CWE-20</a> number')
							expect(@cvedetails_filter.output).to include('invalid cwe-invalid invalid')
						end
					end #cwe 
				end #cvedetails

				describe "custom filter" do
			        specify "config should merge correctly" do
			        	expect(Jekyll::Secinfo::Config.get(@site.config,@custom_filter.data)).to eq(
			        		{
			        			"cve"=>{"url"=>"https://localhost/%s/details"},
			        			"cwe" => {"url"=>"https://localhost/%s/details"},
				        		"divd" => {"url"=>"https://localhost/%s/details"}
			        		}
			        	)
			        end

					describe "cve filters" do
						specify "should all be gone" do
							expect(@custom_filter.output).not_to include("cve }}")
							expect(@custom_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
							expect(@custom_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
							expect(@custom_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
							expect(@custom_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@custom_filter.output).to include('full <a href="https://localhost/2020-8200/details" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@custom_filter.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@custom_filter.output).to include('number <a href="https://localhost/2000-1206/details" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@custom_filter.output).to include('invalid cve-invalid invalid')
						end
					end

					describe "cwe filters" do
						specify "should all be gone" do
							expect(@custom_filter.output).not_to include("cwe }}")
							expect(@custom_filter.output).not_to include('full {% "CWE-79" | cwe %} full')
							expect(@custom_filter.output).not_to include('lower {% "cwe-787" | cwe %} lower')
							expect(@custom_filter.output).not_to include('number {% "20" | cwe %} number')
							expect(@custom_filter.output).not_to include('invalid {% "cwe-invalid" | cwe %} invalid')
						end

						specify "should all be rendered correctly" do
							expect(@custom_filter.output).to include('full <a href="https://localhost/2020-8200/details" class="cve secinfo">CVE-2020-8200</a> full')
							expect(@custom_filter.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve secinfo">CVE-2018-20808</a> lower')
							expect(@custom_filter.output).to include('number <a href="https://localhost/2000-1206/details" class="cve secinfo">CVE-2000-1206</a> number')
							expect(@custom_filter.output).to include('invalid cwe-invalid invalid')
						end
					end #cwe 			
				end #custom
=begin
=end
        	end #type
      	end #end site
    end 
  
end

