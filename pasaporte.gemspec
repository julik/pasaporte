# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{pasaporte}
  s.version = "0.0.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Julik Tarkhanov"]
  s.date = %q{2009-02-14}
  s.description = %q{An OpenID server with a colored bar on top}
  s.email = %q{me@julik.nl}
  s.executables = ["pasaporte-emit-app.rb", "pasaporte-fcgi.rb"]
  s.extra_rdoc_files = ["History.txt", "Manifest.txt", "README.txt", "TODO.txt"]
  s.files = ["History.txt", "Manifest.txt", "README.txt", "Rakefile", "TODO.txt", "bin/pasaporte-emit-app.rb", "bin/pasaporte-fcgi.rb", "lib/pasaporte.rb", "lib/pasaporte/assets/bgbar.png", "lib/pasaporte/assets/lock.png", "lib/pasaporte/assets/mainbg_green.gif", "lib/pasaporte/assets/mainbg_red.gif", "lib/pasaporte/assets/openid.png", "lib/pasaporte/assets/pasaporte.css", "lib/pasaporte/assets/pasaporte.js", "lib/pasaporte/assets/user.png", "lib/pasaporte/auth/cascade.rb", "lib/pasaporte/auth/remote_web_workplace.rb", "lib/pasaporte/auth/yaml_digest_table.rb", "lib/pasaporte/auth/yaml_table.rb", "lib/pasaporte/faster_openid.rb", "lib/pasaporte/hacks.rb", "lib/pasaporte/iso_countries.yml", "lib/pasaporte/julik_state.rb", "lib/pasaporte/lighttpd/cacert.pem", "lib/pasaporte/lighttpd/cert_localhost_combined.pem", "lib/pasaporte/lighttpd/sample-lighttpd-config.conf", "lib/pasaporte/markaby_ext.rb", "lib/pasaporte/models.rb", "lib/pasaporte/pasaporte_store.rb", "lib/pasaporte/timezones.yml", "lib/pasaporte/token_box.rb", "test/fixtures/pasaporte_approvals.yml", "test/fixtures/pasaporte_profiles.yml", "test/fixtures/pasaporte_throttles.yml", "test/helper.rb", "test/mosquito.rb", "test/test_approval.rb", "test/test_auth_backends.rb", "test/test_edit_profile.rb", "test/test_openid.rb", "test/test_pasaporte.rb", "test/test_profile.rb", "test/test_public_signon.rb", "test/test_settings.rb", "test/test_signout.rb", "test/test_throttle.rb", "test/test_token_box.rb", "test/test_with_partial_ssl.rb", "test/testable_openid_fetcher.rb"]
  s.has_rdoc = true
  s.homepage = %q{http://pasaporte.rubyforge.org}
  s.rdoc_options = ["--main", "README.txt", "--charset", "utf-8"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{pasaporte}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{Downgrades the OpenID providing business to the usual login-password stupidity.}
  s.test_files = ["test/test_approval.rb", "test/test_auth_backends.rb", "test/test_edit_profile.rb", "test/test_openid.rb", "test/test_pasaporte.rb", "test/test_profile.rb", "test/test_public_signon.rb", "test/test_settings.rb", "test/test_signout.rb", "test/test_throttle.rb", "test/test_token_box.rb", "test/test_with_partial_ssl.rb"]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activerecord>, [">= 0"])
      s.add_runtime_dependency(%q<camping>=1.5.180>, [">= 0"])
      s.add_runtime_dependency(%q<ruby-openid>, [">= 2.1.0"])
      s.add_runtime_dependency(%q<flexmock>, [">= 0"])
      s.add_development_dependency(%q<hoe>, [">= 1.8.3"])
    else
      s.add_dependency(%q<activerecord>, [">= 0"])
      s.add_dependency(%q<camping>=1.5.180>, [">= 0"])
      s.add_dependency(%q<ruby-openid>, [">= 2.1.0"])
      s.add_dependency(%q<flexmock>, [">= 0"])
      s.add_dependency(%q<hoe>, [">= 1.8.3"])
    end
  else
    s.add_dependency(%q<activerecord>, [">= 0"])
    s.add_dependency(%q<camping>=1.5.180>, [">= 0"])
    s.add_dependency(%q<ruby-openid>, [">= 2.1.0"])
    s.add_dependency(%q<flexmock>, [">= 0"])
    s.add_dependency(%q<hoe>, [">= 1.8.3"])
  end
end
