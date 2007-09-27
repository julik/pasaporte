# Authenticate agains a simple YAML table of logins-passwords per domain. Don't forget
# the dash to begin a new entry!
#
#   google.com: 
#   - :login: george
#     :pass: foo
#   - :login: james
#     :pass: trinkle
#
# Place the table in 'pasaporte/users_per_domain.yml'   
class Pasaporte::Auth::YamlTable
  YAML_TABLE = File.dirname(Pasaporte::PATH) + '/pasaporte/users_per_domain.yml'
  attr_accessor :table_path
  
  def table_path
    @table_path || YAML_TABLE
  end
  
  def initialize
    refresh
  end
  
  def call(login, pass, domain)
    refresh
    d = @table[domain]
    return false unless d.is_a?(Array)
    u = d.find do | user |
      (user["login"] == login) && (user["pass"] == pass)
    end
    !!u
  end
  
  private
    def refresh
      mt = File.stat(table_path).mtime.to_i
      if @modtime && (@modtime == mt)
        return
      else
        f, @modtime = File.read(table_path), mt
        @table = YAML::load(f)
      end
    end
end