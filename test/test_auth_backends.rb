require File.dirname(__FILE__) + '/helper'

silence_warnings do
  require 'auth/yaml_table'
  require 'auth/yaml_digest_table'
end

class TestAuthBackends < Camping::ModelTest
  STORE = File.dirname(Pasaporte::PATH) + '/pasaporte'
  YAML_T = STORE + '/users_per_domain.yml'
  
  def test_yaml_table
    h = {}
    h["test.foo"] = [{"login" => 'schmutz', "pass" => "xx"}]
    h["test.bar"] = [{"login" => 'schtolz', "pass" => "xx"}]
    File.open(YAML_T, 'w') { | f | f << h.to_yaml }
    
    auth = Pasaporte::Auth::YamlTable.new
    deny auth.call("foo", "bar", "xxx.com")
    deny auth.call("schmutz", "xx", "test.bar")

    assert auth.call("schmutz", "xx", "test.foo")
    assert auth.call("schtolz", "xx", "test.bar")
  end
  
# def test_yaml_table_with_implicit_reload
#   h = {}
#   h["test.foo"] = [{"login" => 'schmutz', "pass" => "xx"}]
#   File.open(YAML_T, 'w') { | f | f << h.to_yaml }
#   
#   auth = Pasaporte::Auth::YamlTable.new
#   
#   assert auth.call("schmutz", "xx", "test.foo"), "Schmutz is in the table"
#   deny auth.call("schtolz", "xx", "test.foo"), "This guy is not listed in the table yet"
#   
#   h["test.foo"] << {"login" => 'schtolz', "pass" => "xx"} 
#   File.open(YAML_T, 'w') { | f | f << h.to_yaml }
#   
#   assert auth.call("schtolz", "xx", "test.foo"), "Schtolz is now in"
# end
  
  def test_yaml_digest_table
    h = {}
    h["test.foo"] = [{"login" => 'schmutz', "pass_md5" => _md5("xyz")}]
    h["test.bar"] = [{"login" => 'schtolz', "pass_md5" => _md5("watoi")}]
    File.open(YAML_T, 'w') { | f | f << h.to_yaml }
    
    auth = Pasaporte::Auth::YamlDigestTable.new
  end
  
  def teardown
    FileUtils.rm_rf(YAML_T) rescue Errno::ENOENT
    super
  end
  
  def _md5(x)
    Digest::MD5.hexdigest(x).to_s
  end
end