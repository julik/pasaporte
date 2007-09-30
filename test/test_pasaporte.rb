require File.dirname(__FILE__) + '/helper'
require 'flexmock'

class TestProfilePage < Pasaporte::WebTest
  fixtures :pasaporte_profiles

  def test_user_info_page_for_user_who_never_logged_in
    get '/unknown-stranger'
    assert_response :success
    assert_select "h3", true do | h |
      assert_equal "<h3>This is <b>unknown-stranger's</b> page</h3>", h.to_s
    end
  end
  
  def test_user_info_page_for_a_user_who_is_in_hiding
    get '/julik'
    assert_response :success
    assert_select "h3", true do | h |
      assert_equal "<h3>This is <b>julik's</b> page</h3>", h.to_s
    end
  end
  
  def test_user_info_page_for_a_user_who_shows_his_profile
    max = Profile.find(3)
    assert max.shared?, "Max shares his profile"
    get '/max'
    assert_equal max.domain_name, @request.domain
    assert_response :success
    assert_not_nil @assigns.profile
    
    assert_select "h2", true do | h |
      assert_equal "<h2>Max Lapshin</h2>", h.to_s
    end
    assert_match_body /Promised to/
  end
  
  def test_user_info_depends_on_domain
    get '/max'
    assert_response :success
    assert_not_nil @assigns.profile
    
    @request.domain = "trashcan.dot"
    get '/max'
    assert_response :success
    assert_nil @assigns.profile, "A profile page for someone who never logged in does not show any details"
  end
    
end

class TestSignon < Pasaporte::WebTest
  fixtures :pasaporte_profiles
  
  def teardown
    returning(super) {Throttle.delete_all }
  end
  
  def test_signon_displays_a_password_field
    get '/julik/signon'
    assert_response :success
    assert_select "input[type=password]", true
  end
  
  def test_posting_to_signon_should_call_auth_and_fail
    flexmock(Pasaporte::AUTH).
        should_receive(:call).with("julik", "trance", "test.host").
        at_least.once.and_return(false)
    
    post '/julik/signon', :pass => "trance"
    assert_response :success
    assert_not_nil @assigns.msg, "Something should be put into msg"
    assert_nil @state.nickname, "Nickname should not have been set in the session"
    assert_not_nil @state.failed_logins, "The signon should start counting failed logins" 
    assert_equal 1, @state.failed_logins, "The signon should have counted 1 failed login" 
  end
  
  def test_posting_false_login_many_times_winds_the_failed_login_counter
    flexmock(Pasaporte::AUTH).
        should_receive(:call).with("julik", "trance", "test.host").
        at_least.twice.and_return(false)
    post '/julik/signon', :pass => "trance"
    post '/julik/signon', :pass => "trance"
    assert_equal 2, @state.failed_logins, "The failed login counter should have been wound" 
  end
  
  def test_past_the_failed_login_threshold_should_trottle
    flexmock(Pasaporte::AUTH).
        should_receive(:call).with("julik", "trance", "test.host").at_least.once.and_return(false)
    
    Pasaporte::MAX_FAILED_LOGIN_ATTEMPTS.times { post '/julik/signon', :pass => "trance" }
    assert_response :success
    assert_match_body /I am stopping you/, "The throttling message should appear"
    assert_equal 1, Throttle.count, "A throttle should have been made"
  end
  
  def test_post_with_good_auth_shold_fetch_profile_munge_session_and_redirect
    flexmock(Pasaporte::AUTH).
        should_receive(:call).with("julik", "junkman", "test.host").once.and_return(true)
    
    post '/julik/signon', :pass => 'junkman'
    
    assert_response :redirect
    assert_redirected_to '/julik/edit'
    
    assert_not_nil @assigns.profile, "The profile should have been hooked up"
    assert_equal 2, @assigns.profile.id, "This is Julik's profile"
    assert_equal 'julik', @state.nickname, "The nickname should be set to 'julik' so that the flag is present"
  end
  
  def test_post_with_good_auth_should_create_profiles_if_necessary
    flexmock(Pasaporte::AUTH).
        should_receive(:call).with("gemanges", "tairn", "test.host").once.and_return(true)
    
    post '/gemanges/signon', :pass => 'tairn'
    assert_response :redirect
    
    assert_not_nil @assigns.profile, "The profile should have been hooked up"
    assert_equal 'gemanges', @assigns.profile.nickname
    deny @assigns.profile.new_record?
  end
end

class TestSignout < Pasaporte::WebTest
  def test_signout_should_silently_redirect_unless_signed_in
    get '/somebody/signout'
    assert_response :redirect
    assert_redirected_to '/somebody/signon'
  end
  
  def test_signout_should_erase_session_and_redirect
    flexmock(Pasaporte::AUTH).
        should_receive(:call).with("gemanges", "tairn", "test.host").once.and_return(true)
    post '/gemanges/signon', :pass => 'tairn'
    assert_response :redirect
    assert_equal 'gemanges', @state.nickname
    
    get '/gemanges/signout'
    assert_response :redirect
    assert_redirected_to '/gemanges/signon'
    assert_kind_of Camping::H, @state, "State should be reset with Camping::H"
    assert_equal %w( msg ), @state.keys, "State should only contain the message"
  end
end