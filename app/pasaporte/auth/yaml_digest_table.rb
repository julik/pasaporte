# Authenticate agains a simple YAML table of logins-passwords per domain. Don't forget
# the dash to begin a new entry!
#
#   google.com: 
#   - :login: george
#     :pass_md5: acbd18db4cc2f85cedef654fccc4a4d8
#   - :login: james
#     :pass_md5: ceba333c1d30a6dd94a57f9d34d73ff7
#
# Place the table in 'pasaporte/users_per_domain.yml'   
require File.dirname(__FILE__) + '/yaml_table'
require 'digest/md5'

class Pasaporte::Auth::YamlDigestTable < Pasaporte::Auth::YamlTable
  def call(login, pass, domain)
    refresh
    d = @table[domain]
    return false unless d.is_a?(Array)
    d.find do | user |
      (user["login"] == login) && (user["pass_md5"] == Digest::MD5.hexdigest(pass))
    end
  end
end