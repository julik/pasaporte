require File.dirname(__FILE__) + '/helper'

class TestPublicSignon < Pasaporte::WebTest
  fixtures :pasaporte_profiles
  test 'should present a login screen without predefined nickname' do
    get
    assert_response :success
    assert_select 'input[name="login"]', true
    
    flexmock(Pasaporte::AUTH).should_receive(:call).with("schtwo", "foo", "test.host").and_return(false)
    
    post '/', :login => 'schtwo', :pass => 'foo'
    assert_response :success
    assert_nil @state.nickname
    assert_select 'input[value="schtwo"]', true
  end
  
  test 'should redirect to profile page for new users' do
    flexmock(Pasaporte::AUTH).should_receive(:call).with("unknown", "pfew", "test.host").and_return(true)
    post '/', :login => "unknown", :pass => "pfew"
    assert_response :redirect
    assert_not_nil Profile.find_by_nickname('unknown'), "A profile should have been created during login"
    assert_redirected_to '/unknown/prefs'
  end
  
end