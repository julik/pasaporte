# =begin
# ActiveDirectory-Exchange-Blaggh authentication guerilla-style. Will take the give username and password and try to authenticate
# them against the given Remote Web Workplace server. This assumes that the user on a domain also has an email address
# with OWA of course. If the user is found RWW will give us a specific response. No credentials or user information is
# retrieved.
# =end
class RemoteWebWorkplace
  attr_accessor :use_ssl

  VIEW_STATE_PAT =  /name="__VIEWSTATE" value="([^"]+)"/
  LOGIN_URL = "/Remote/logon.aspx"
  BASE_LOGIN_URL = '/Remote/logon.aspx?ReturnUrl=%2fRemote%2fDefault.aspx'
  
  def initialize(server)
    @server = server
    require 'net/http'
    require 'net/https'
  end
  
  # Will run the auth
  def logs_in?(user, password)
    
    @http = (@use_ssl? ? Net::HTTPS : Net::HTTP).new(@server, (@use_ssl ? 443 : 80))
    
    with_viewstate_and_connection(@http) do | payload |
      login_form_values  = {
        "txtUserName" => user.to_s,
        "txtUserPass" => password.to_s,
        "cmdLogin" => "cmdLogin",
        "listSpeed" => "Broadband",
        "__VIEWSTATE" => payload,
      }
      
      begin
        @http.start do |http|
          form_post = Net::HTTP::Post.new(LOGIN_URL)
          form_post.set_form_data(login_form_values, '&')
          response = http.request(form_post); response.value
        end
      rescue Net::HTTPRetriableError => e
        if e.message =~ /302/ # RWW will return a redirect if the user is found
          return true
        end
      end
      return false
    end
  end
  
  private
    def with_viewstate_and_connection(conn)
      begin
        viewstate_payload = conn.start do |http|
          response = http.get(@base_login_url); response.value
          response.body.scan(VIEW_STATE_PAT).pop.pop
        end
        yield viewstate_payload
      rescue SocketError => e
        raise "Cannot connect to Outlook Web Access at #{@server}: #{e.message}"
      end
    end
end