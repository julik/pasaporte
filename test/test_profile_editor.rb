require File.dirname(__FILE__) + '/helper'
require File.dirname(__FILE__) + '/testable_openid_fetcher'

require 'flexmock'

class TestProfileEditor < Pasaporte::WebTest
  test 'should require login' do
    get '/julik/edit'
    assert_response :redirect
    assert_redirected_to '/julik/signon'
  end
  
  test 'should preload profile' do
    prelogin 'julik'
    get '/julik/edit'
    assert_response :success
    assert_kind_of Profile, @assigns.profile
    deny @assigns.profile.new_record?, "This is a presaved profile"
    assert_match_body /Your profile/
  end
  
  test 'should show message and not save when posting faulty data' do
    prelogin 'julik'
    post '/julik/edit', :profile => {:openid_server => 'xyz'}
    
    assert_response :success
    assert_not_nil @assigns.err, "An error message should be assigned"
    assert_match /Cannot save/, @assigns.err, "The error message should describe the problem"
    
    prof = @assigns.profile
    prof.reload
    assert_nil prof.openid_server, "Nothing should have been assigned"
  end
  
  test 'should redirect with success message when changing the profile succeeds' do
    prelogin 'julik'
    post '/julik/edit', :profile => {:email => 'trof@groff.com'}
    assert_response :redirect
    assert_not_nil @state.msg
    assert_match /Changed/i, @state.msg
  end
  
  test 'default country should be selected when loading the profile page for the first time' do
    prelogin 'joe-boss'
    
    begin
      c = Pasaporte::DEFAULT_COUNTRY
      silence_warnings { Pasaporte.const_set(:DEFAULT_COUNTRY, 'us')}
      get '/joe-boss/edit'
      assert_response :success
      assert_select 'option[value="us"][selected]', true
    ensure
      silence_warnings { Pasaporte.const_set(:DEFAULT_COUNTRY, c) }
    end
  end
  
end