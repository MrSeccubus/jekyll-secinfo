# frozen_string_literal: true

RSpec.describe(Jekyll::Secinfo) do
  Jekyll.logger.log_level = :error

  let(:config_overrides) { {} }
  let(:configs) do
    Jekyll.configuration(
      config_overrides.merge(
        "skip_config_files" => false,
        #{}"collections"       => { "docs" => { "output" => true } },
        "source"            => fixtures_dir,
        "destination"       => fixtures_dir("_site")
      )
    )
  end

  let(:secinfo)             { described_class }
  let(:site)                { Jekyll::Site.new(configs) }
  let(:posts)               { site.posts.docs.sort.reverse }

  let(:index_page)          { find_by_title(site.pages, "I'm a page") }
  let(:mitre_page)          { find_by_title(site.pages, "Mitre style") }
  let(:weird_page)          { find_by_title(site.pages, "Weird style") }
  let(:nvd_page)            { find_by_title(site.pages, "NVD style") }
  let(:cvedetails_page)     { find_by_title(site.pages, "CVEdetails style") }
  let(:custom_page)         { find_by_title(site.pages, "Custom style") }

  let(:default_filter)      { find_by_title(site.pages, "Default filter page") }
  let(:mitre_filter)        { find_by_title(site.pages, "Mitre filter page") }
  let(:weird_filter)        { find_by_title(site.pages, "Wierd filter page") }
  let(:nvd_filter)          { find_by_title(site.pages, "NVD filter page") }
  let(:cvedetails_filter)   { find_by_title(site.pages, "CVEdetails filter page") }
  let(:custom_filter)       { find_by_title(site.pages, "Custom filter page") }
  

=begin
  let(:default_src) { "https://github.com" }
  let(:unrendered)  { "test @TestUser test" }
  let(:result)      { "test <a href=\"https://github.com/TestUser\" class=\"user-mention\">@TestUser</a> test" }

  let(:basic_post)   { find_by_title(posts, "I'm a post") }
  let(:complex_post) { find_by_title(posts, "Code Block") }

  let(:basic_doc) { find_by_title(site.collections["docs"].docs, "File") }
  let(:doc_with_liquid) { find_by_title(site.collections["docs"].docs, "With Liquid") }
  let(:txt_doc) { find_by_title(site.collections["docs"].docs, "Don't Touch Me") }
  let(:spl_chars_doc) { find_by_title(site.collections["docs"].docs, "Unconventional Names") }
  let(:minified_page) { find_by_title(site.pages, "I'm minified!") }
  let(:disabled_mentioning_page) { find_by_title(site.pages, "ignore all mentions") }
  let(:custom_url_01) { find_by_title(site.pages, "custom URL 01") }
  let(:custom_url_02) { find_by_title(site.pages, "custom URL 02") }

  def para(content)
    "<p>#{content}</p>"
  end
=end
  before(:each) do
    site.reset
    site.read
    (site.pages | posts | site.docs_to_write).each { |p| p.content.strip! }
    site.render
  end

  it "all {\% cve tags should be gone from index page" do
    expect(index_page.output).not_to include("{\% cve")
    expect(index_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
    expect(index_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
    expect(index_page.output).not_to include('number {% cve: 2021-00003 %} number')
    expect(index_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
  end

  it "all {\% cve tags should be replace in index page" do
    expect(index_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(index_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(index_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(index_page.output).to include('invalid cve-invalid  invalid')
  end

  it "all {\% cve tags should be gone from mitre page" do
    expect(mitre_page.output).not_to include("{\% cve")
    expect(mitre_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
    expect(mitre_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
    expect(mitre_page.output).not_to include('number {% cve: 2021-00003 %} number')
    expect(mitre_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
  end

  it "all {\% cve tags should be replace in mitre page" do
    expect(mitre_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(mitre_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(mitre_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(mitre_page.output).to include('invalid cve-invalid  invalid')
  end

  it "all {\% cve tags should be gone from weird page" do
    expect(weird_page.output).not_to include("{\% cve")
    expect(weird_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
    expect(weird_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
    expect(weird_page.output).not_to include('number {% cve: 2021-00003 %} number')
    expect(weird_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
  end

  it "all {\% cve tags should be replace in weird page" do
    expect(weird_page.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(weird_page.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(weird_page.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(weird_page.output).to include('invalid cve-invalid  invalid')
  end

  it "all {\% cve tags should be gone from nvd page" do
    expect(nvd_page.output).not_to include("{\% cve")
    expect(nvd_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
    expect(nvd_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
    expect(nvd_page.output).not_to include('number {% cve: 2021-00003 %} number')
    expect(nvd_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
  end

  it "all {\% cve tags should be replace in nvd page" do
    expect(nvd_page.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(nvd_page.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(nvd_page.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(nvd_page.output).to include('invalid cve-invalid  invalid')
  end

  it "all {\% cve tags should be gone from cvedetails page" do
    expect(cvedetails_page.output).not_to include("{\% cve")
    expect(cvedetails_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
    expect(cvedetails_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
    expect(cvedetails_page.output).not_to include('number {% cve: 2021-00003 %} number')
    expect(cvedetails_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
  end

  it "all {\% cve tags should be replace in cvedetails page" do
    expect(cvedetails_page.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve">CVE-2020-8200</a> full')
    expect(cvedetails_page.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve">CVE-2018-20808</a> lower')
    expect(cvedetails_page.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve">CVE-2000-1206</a> number')
    expect(cvedetails_page.output).to include('invalid cve-invalid  invalid')
  end

  it "all {\% cve tags should be gone from custom page" do
    expect(custom_page.output).not_to include("{\% cve")
    expect(custom_page.output).not_to include('full {% cve: CVE-2021-00001 %} full')
    expect(custom_page.output).not_to include('lower {% cve: cve-2021-00002 %} lower')
    expect(custom_page.output).not_to include('number {% cve: 2021-00003 %} number')
    expect(custom_page.output).not_to include('invalid {% cve: cve-invalid %} invalid')
  end

  it "all {\% cve tags should be replace in custom page" do
    expect(custom_page.output).to include('full <a href="https://localhost/2020-8200/details" class="cve">CVE-2020-8200</a> full')
    expect(custom_page.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve">CVE-2018-20808</a> lower')
    expect(custom_page.output).to include('number <a href="https://localhost/2000-1206/details" class="cve">CVE-2000-1206</a> number')
    expect(custom_page.output).to include('invalid cve-invalid  invalid')
  end





  #
  # Filters
  #
  it "all {{ tags should be gone from default filter page" do
    expect(default_filter.output).not_to include("cve }}")
    expect(default_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
    expect(default_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
    expect(default_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
    expect(default_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
  end

  it "all {{ tags should be replace in default filter page" do
    expect(default_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(default_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(default_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(default_filter.output).to include('invalid cve-invalid invalid')
  end

  it "all {{ tags should be gone from mitre filter page" do
    expect(mitre_filter.output).not_to include("cve }}")
    expect(mitre_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
    expect(mitre_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
    expect(mitre_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
    expect(mitre_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
  end

  it "all {{ cve tags should be replace in mitre filter page" do
    expect(mitre_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(mitre_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(mitre_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(mitre_filter.output).to include('invalid cve-invalid invalid')
  end


  it "all {{ tags should be gone from weird filter page" do
    expect(weird_filter.output).not_to include("cve }}")
    expect(weird_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
    expect(weird_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
    expect(weird_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
    expect(weird_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
  end

  it "all {{ cve tags should be replace in weird filter page" do
    expect(weird_filter.output).to include('full <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(weird_filter.output).to include('lower <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(weird_filter.output).to include('number <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(weird_filter.output).to include('invalid cve-invalid invalid')
  end

  it "all {{ tags should be gone from nvd filter page" do
    expect(nvd_filter.output).not_to include("cve }}")
    expect(nvd_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
    expect(nvd_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
    expect(nvd_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
    expect(nvd_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
  end

  it "all {{ cve tags should be replace in nvd filter page" do
    expect(nvd_filter.output).to include('full <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-8200" class="cve">CVE-2020-8200</a> full')
    expect(nvd_filter.output).to include('lower <a href="https://nvd.nist.gov/vuln/detail/CVE-2018-20808" class="cve">CVE-2018-20808</a> lower')
    expect(nvd_filter.output).to include('number <a href="https://nvd.nist.gov/vuln/detail/CVE-2000-1206" class="cve">CVE-2000-1206</a> number')
    expect(nvd_filter.output).to include('invalid cve-invalid invalid')
  end

  it "all {{ tags should be gone from cvedetails filter page" do
    expect(cvedetails_filter.output).not_to include("cve }}")
    expect(cvedetails_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
    expect(cvedetails_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
    expect(cvedetails_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
    expect(cvedetails_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
  end

  it "all {{ cve tags should be replace in cvedetails filter page" do
    expect(cvedetails_filter.output).to include('full <a href="https://www.cvedetails.com/cve/CVE-2020-8200/" class="cve">CVE-2020-8200</a> full')
    expect(cvedetails_filter.output).to include('lower <a href="https://www.cvedetails.com/cve/CVE-2018-20808/" class="cve">CVE-2018-20808</a> lower')
    expect(cvedetails_filter.output).to include('number <a href="https://www.cvedetails.com/cve/CVE-2000-1206/" class="cve">CVE-2000-1206</a> number')
    expect(cvedetails_filter.output).to include('invalid cve-invalid invalid')
  end

  it "all {{ tags should be gone from custom filter page" do
    expect(custom_filter.output).not_to include("cve }}")
    expect(custom_filter.output).not_to include('full {{ "CVE-2020-8200" | cve }} full')
    expect(custom_filter.output).not_to include('lower {{ "cve-2018-20808" | cve }} lower')
    expect(custom_filter.output).not_to include('number {{ "2000-1206" | cve }} number')
    expect(custom_filter.output).not_to include('invalid {{ "cve-invalid" | cve }} invalid')
  end

  it "all {{ cve tags should be replace in custom filter page" do
    expect(custom_filter.output).to include('full <a href="https://localhost/2020-8200/details" class="cve">CVE-2020-8200</a> full')
    expect(custom_filter.output).to include('lower <a href="https://localhost/2018-20808/details" class="cve">CVE-2018-20808</a> lower')
    expect(custom_filter.output).to include('number <a href="https://localhost/2000-1206/details" class="cve">CVE-2000-1206</a> number')
    expect(cvedetails_filter.output).to include('invalid cve-invalid invalid')
  end



end