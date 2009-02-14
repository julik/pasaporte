require File.dirname(__FILE__) + '/helper'

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
    # TODO: why err is still here??
    assert_equal %w( msg err ), @state.keys, "State should only contain the message and error"
  end
end