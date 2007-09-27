require 'helper'
class TestSettings < Test::Unit::TestCase
  CONFIG = File.dirname(Pasaporte::PATH) + '/pasaporte/config.yml'
  
  def test_application
    emit :throttle_for => 45.minutes
    assert_nothing_raised { Pasaporte.apply_config! }
    assert_equal 45.minutes, Pasaporte::THROTTLE_FOR, "The setting should have " + 
      "been applied"
  end
  
  def test_bail_on_unknowns
    emit :achtung => "shtoink"
    e = assert_raise(NameError) { Pasaporte.apply_config! }
    assert_match /ACHTUNG/i, e.message
  end
  
  def teardown
    begin; File.unlink(CONFIG); rescue Errno::ENOENT; end
  end
  
  private
    def emit(hash = {})
      File.open(CONFIG, 'w') { | f | f << hash.to_yaml }
    end
end