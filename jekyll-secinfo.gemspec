# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jekyll-secinfo/version'

Gem::Specification.new do |spec|
  spec.name          = "jekyll-secinfo"
  spec.version       = Jekyll::Secinfo::VERSION
  spec.authors       = ["Frank Breedijk"]
  spec.email         = ["fbreedijk@schubergphilis.com"]

  spec.summary       = %q{jekyll plugin to generate html snippets various security info}
  spec.description   = %q{This Jekyll plugin to generate html snippets for clickable security information tags like CVEs and CWEs}
  spec.homepage      = "https://github.com/MrSeccubus/jekyll-secinfo"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ["lib"]

  spec.add_dependency 'jekyll'
  spec.add_dependency "rainbow", "~> 3"

  spec.add_development_dependency "bundler", "~> 2.1"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop-jekyll", "~> 0.4"
end
