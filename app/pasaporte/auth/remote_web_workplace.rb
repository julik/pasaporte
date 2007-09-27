=begin
ActiveDirectory-Exchange-Blaggh authentication guerilla-style. Will take the give username and password and try to authenticate
them against the give Remote Web Workplace server. This assumes that the user on a domain also has an email address
with OWA of course. If the user is found RWW will give us a specific response. No credentials or user information is
retrieved.
=end
class Pasaporte::Auth::RemoteWebWorkplace
  # A proc that should translate the name of the Pasaporte domain
  # to the name of the Outlook Web Exchange server. For example:
  # remote_web_server_name_proc = lambda {|d| "web-workplace.%s" % d }
  attr_accessor :remote_web_server_name_proc
  attr_accessor :server, :use_ssl

  VIEW_STATE_PAT =  /name="__VIEWSTATE" value="([^"]+)"/
  LOGIN_URL = "/Remote/logon.aspx"
  BASE_LOGIN_URL = '/Remote/logon.aspx?ReturnUrl=%2fRemote%2fDefault.aspx'
  
  def initialize
    require 'net/http'
    require 'net/https'
    @remote_web_server_name_proc = lambda do | domain |
      # Prepend the domain name with "mail"
      ["mail", domain].join('.')
    end
  end
  
  # Will run the auth
  def call(user, password, domain)
    @domain = domain
    with_viewstate do | payload |
      login_form_values  = {
        "txtUserName" => user.to_s,
        "txtUserPass" => password.to_s,
        "cmdLogin" => "cmdLogin",
        "listSpeed" => "Broadband",
        "__VIEWSTATE" => payload,
      }
      
      begin
        remote_web_workplace_http.start do |http|
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
    def remote_web_workplace_http
      Net::HTTP.new(remote_web_server_name_proc.call(@domain), (@use_ssl ? 443 : 80))
    end
    
    def with_viewstate
      viewstate_payload = remote_web_workplace_http.start do |http|
        request = Net::HTTP::Get.new(@base_login_url)
        response = http.request(request); response.value
        response.body.scan(VIEW_STATE_PAT).pop.pop
      end
      yield viewstate_payload
    end
end