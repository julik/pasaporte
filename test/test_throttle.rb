require File.dirname(__FILE__) + '/helper'

class TestThrottle < Camping::ModelTest
  DOMAIN = 'my-pasaporte.com'
  HEADERS = Mosquito::MockRequest::DEFAULT_HEADERS.merge('REMOTE_ADDR' => '120.171.0.1')
  
  def setup
    silence_warnings { Pasaporte.const_set(:THROTTLE_FOR, 2.minutes) }
    super
  end
  
  def test_throttle_set
    deny Throttle.throttled?(HEADERS)
    
    t = Throttle.set!(HEADERS)
    assert_kind_of Throttle, t
    deny t.new_record?
    assert Throttle.throttled?(HEADERS)
  end

  def test_throttle_response_depends_on_cutoff
    Throttle.set!(HEADERS)
    flexmock(Throttle).should_receive(:cutoff).at_least.once.and_return(Time.now + 10)
    deny Throttle.throttled?(HEADERS)
  end
  
  def test_cutoff_depends_on_app_setting
    assert_time_matches (Time.now - Pasaporte::THROTTLE_FOR), Throttle.send(:cutoff)
    silence_warnings{ Pasaporte.const_set(:THROTTLE_FOR, 14) }
    assert_time_matches Time.now - 14, Throttle.send(:cutoff)
  end
  
  def test_throttle_response_depends_on_env_params
    envs = [
      {'HTTP_USER_AGENT' => 'KitchenSink, NOT like IE',  
          'REMOTE_ADDR' => '164.10.10.1'},
      {'HTTP_USER_AGENT' => 'WebKit (like Gecko)',
          'REMOTE_ADDR' => '164.10.10.1'},
      {'HTTP_USER_AGENT' => 'KitchenSink, NOT like IE',  
          'REMOTE_ADDR' => '164.10.10.1'},
    ]
    
    Throttle.set!(envs[0])
    assert Throttle.throttled?(envs[0])
    assert Throttle.throttled?(envs[2])
    deny Throttle.throttled?(envs[1]), "This environment is not throttled"
  end
  
  def teardown
    Throttle.delete_all
    super
  end
  
  def test_throttle_autoexpiry_on_check
    Throttle.set!(HEADERS)
    assert_equal 1, Throttle.count
    flexmock(Throttle).should_receive(:cutoff).at_least.once.and_return(Time.now + 10)
    
    deny Throttle.throttled?(HEADERS)
    assert_equal 0, Throttle.count
  end
  
  private
    def assert_time_matches(ref, actual)
      assert_kind_of Time, ref, "The reference value should be Time"
      assert_kind_of Time, actual, "The actual value should be Time"
      assert_in_delta(ref.to_i, actual.to_i,  2, 
        "The times passed should be within 2s")
    end
end