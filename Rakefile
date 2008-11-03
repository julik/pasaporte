$:.reject! { |e| e.include? 'TextMate' }
require 'rubygems'
require 'hoe'
require File.dirname(__FILE__) + '/lib/pasaporte'
$KCODE = 'u'

class KolkHoe < Hoe
  def define_tasks
    extra_deps.reject! {|e| e[0] == 'hoe' }
    super
  end
end

# Disable spurious warnings when running tests, ActiveMagic cannot stand -w
Hoe::RUBY_FLAGS.replace ENV['RUBY_FLAGS'] || "-I#{%w(lib test).join(File::PATH_SEPARATOR)}" + 
  (Hoe::RUBY_DEBUG ? " #{RUBY_DEBUG}" : '')

KolkHoe.new('Pasaporte', Pasaporte::VERSION) do |p|
  p.name = "pasaporte"
  p.author = "Julik Tarkhanov"
  p.description = "An OpenID server with a colored bar on top"
  p.email = 'me@julik.nl'
  p.summary = "Downgrades the OpenID providing business to the usual login-password stupidity."
  p.url = "http://pasaporte.rubyforge.org"
  p.rdoc_pattern = /README.txt|CHANGELOG.txt|lib/
  p.test_globs = 'test/test_*.rb'
  p.need_zip = true
  p.extra_deps = ['activerecord', 'camping', ['ruby-openid', '>=2.1.0'], 'flexmock']
end

desc "Generate the proper list of country codes from the ISO list"
task :build_country_list do
  ISO_LIST = 'http://www.iso.org/iso/iso3166_en_code_lists.txt'
  require 'open-uri'
  require 'iconv'
  
  # By a twist of faith ISO provides the list in, uhm, ISO encoding AND with \\r \\n.
  # line endings. I bet if they could have it formatted it would be Troglodyte Bold.
  # Convert the whole shebang to UTF straight away!
  iso_in_latin1 = open(ISO_LIST).read

  c = Iconv.new('UTF-8', 'ISO-8859-1')
  iso = c.iconv(iso_in_latin1)

  # Remove the bad line breaks
  iso.gsub!(/\r\n/, "\n")
  
  # Throw away the header declaration
  iso = iso.split(/\n\n/).pop.split(/\n/)
  
  # Split ito something machine-readable
  iso.map!{ | line | line.split(/;/) }
  
  # If you use the raw ISO data you ARE SHOUTING IN ALL CAPS which makes everyone feel like an idiot.
  # We have to do something about that.
  iso.map! do | country, code |
    country_for_humans = country.split(/\s/).map do | word |
      # Prevent some abbrevs like U.S. from being casefolded
      if (word.scan(/\./).length == word.scan(/\w/).length)
        word
      elsif %w( OF AND THE).include?(word)
        word.downcase
      else
        word.chars.downcase.capitalize
      end
    end.join(" ")
    
    [code.chars.downcase, country_for_humans].map(&:to_s)
  end
  
  # Assemble the resulting hash and flush it
  outfile = File.dirname(__FILE__) + '/lib/pasaporte/iso_countries.yml'
  File.open(outfile, 'w') do | out |
    out << "# This has been autogenerated from #{ISO_LIST} on #{Time.now}. See Rakefile for details.\n"
    out << "# This file is bonafide UTF-8 for YAML but do not edit it manually!\n"
    out << Hash[*iso.flatten].to_yaml
  end
end

desc "Generate the proper ist of world timezones from the tzinfo database"
task :build_timezone_list do
  require 'open-uri'
  # TODO - this should not be hardcoded because versions change
  TZ_DATA = "ftp://elsie.nci.nih.gov/pub/tzdata2007g.tar.gz"
  
  begin
    FileUtils.mkdir_p(File.dirname(__FILE__) + '/tmp')
    File.open("tmp/tzd.tar.gz", "w") {|f| f << open("ftp://elsie.nci.nih.gov/pub/tzdata2007g.tar.gz").read }
    `cd tmp; tar xfz tzd.tar.gz`
    zone_names = []
    File.open(File.dirname(__FILE__) + '/tmp/zone.tab') do | f |
      f.each_line do | l |
        next if l =~ /#/
        name = l.split(/\t/)[2..-1].join(" ").strip
        next if name.blank?
        # The formal value that is required per sreg' specs comes first.
        # The humanized variant is everything before the first tab, with underscores
        # replaced by spaces
        zone_names << [name, name.split(/\s/).shift.gsub(/_/, ' ')]
      end
    end
    outfile = File.dirname(__FILE__) + '/lib/pasaporte/timezones.yml'
    File.open(outfile, 'w') do | out |
      out << "# This has been autogenerated from #{TZ_DATA} on #{Time.now}. See Rakefile for details.\n"
      out << "# This file is bonafide UTF-8 for YAML but do not edit it manually!\n"
      out << zone_names.to_yaml
    end
  ensure
    FileUtils.rm_rf(File.dirname(__FILE__) + '/tmp')
  end
end