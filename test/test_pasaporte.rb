require File.dirname(__FILE__) + '/helper'

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
  
  def test_user_info_sets_yadis_headers
    get '/julik'
    assert_not_nil @response.headers['X-XRDS-Location']
    assert_equal "http://test.host/pasaporte/julik/yadis", @response.headers['X-XRDS-Location']
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
    assert_redirected_to '/julik/prefs'
    
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

class TestApprovalsPage < Pasaporte::WebTest
  fixtures :pasaporte_profiles, :pasaporte_approvals
  def test_approvals_page_requires_login
    get '/julik/approvals'
    assert_response :redirect
  end
  
  def test_approvals_page_shows_useful_approvals_when_they_are_present
    prelogin "julik"
    
    get '/julik/approvals'
    assert_response :success
    
    assert_equal Profile.find_by_nickname('julik').approvals, @assigns.approvals
    assert_match_body /The sites you trust/
  end
  
  def test_approvals_page_does_not_show_empty_lists
    Profile.find_by_nickname('julik').approvals.destroy_all
    prelogin 'julik'
    get '/julik/approvals'
    assert_redirected_to '/julik/prefs'
    assert_not_nil @state.msg
  end
end

class TestAssets < Pasaporte::WebTest
  def test_get_nonexistent_url_sets_404
    get '/assets/habduda'
    assert_response 404
  end
  
  def test_get_with_dir_traversal
    ref_path = File.dirname(Pasaporte::PATH) + '/pasaporte/assets/etc/passwd'
    
    flexmock(File).should_receive(:exist?).with(ref_path).once.and_return(false)
    get '/assets/../../../../../etc/passwd'
    assert_response 404
  end
  
  def test_should_return_stylesheet
    get '/assets/pasaporte.css'
    assert_response :success
    assert_equal 'text/css', @response.headers['Content-Type'], "Should set the content type to text/css"
    assert_match_body /Superresetthemall/
  end
  
  def test_grabbing_an_asset_sets_magic_headers
    get '/assets/pasaporte.css'
    magic_headers = %w( Last-Modified Expires Cache-Control Last-Modified )
    for h in magic_headers
      assert_not_nil @response.headers[h], "The header #{h} should be set"
    end
  end
  
  def test_should_return_304_on_conditional_get
    @request.headers['HTTP_IF_MODIFIED_SINCE'] = Time.now.to_s(:http)
    get '/assets/pasaporte.css'
    assert_response 304
  end
end


# class TestYadis < Pasaporte::WebTest
#   attr_reader :request, :response
#   fixtures :pasaporte_profiles
#   
#   def setup
#     super; NetHTTPFetcher.requestor = self
#   end
#   
#   test 'should return YADIS info with proper URLs' do
#     get '/julik/yadis'
#     assert_response :success
#     assert_equal "application/xrds+xml",  @response.headers["Content-type"]
#     assert !@response.body.empty?, "Body cannot be empty"
#   end
#   
#   test 'should be usable for yadis discovery' do
#     assert_nothing_raised { @discovery = YADIS.new('http://test.host/julik/yadis') }
#     assert_kind_of ServiceEndpoint, @discovery.services[0]
#     assert_equal "http://test.host/pasaporte/julik/openid", @discovery.services[0].uri
#   end
# 
#   test 'should redirect yadis discovery to the delegate' do
#     assert_nothing_raised { @discovery = YADIS.new('http://test.host/hans/yadis') }
#     assert_kind_of ServiceEndpoint, @discovery.services[0]
#     assert_equal "http://hans.myopenid.com", @discovery.services[0].uri
#   end
# end

# A littol auditte
at_exit do
  missing = Pasaporte::Controllers.constants.reject do |c|
    Object.constants.map{|e|e.to_s}.include?("Test#{c}")
  end
  puts "\nMissing tests for controllers #{missing.to_sentence}"
end