%w( rubygems logger camping camping/session).map{|g| require g }
$: << File.dirname(__FILE__) + '/pasaporte'

Camping.goes :Pasaporte

# Suppress the annoying require_gem warning in ruby-yadis
silence_warnings { require 'openid' }
require 'faster_openid'


module Pasaporte
  MAX_FAILED_LOGIN_ATTEMPTS = 3
  THROTTLE_FOR = 2.minutes
  DEFAULT_COUNTRY = 'nl'
  ALLOW_DELEGATION = true
  VERSION = '0.0.1'
  SESSION_LIFETIME = 10.hours
  
  module Auth; end
  
  LOGGER = Logger.new(STDERR) #:nodoc:
  PATH = File.expand_path(__FILE__) #:nodoc:
  
  # Stick your super auth HERE. Should be a proc accepting login, pass and domain
  my_little_auth = lambda do | login, pass, domain |
    allowd = {"julian" => "useless"}
    return (allowd[login] && (allowd[login] == pass))
  end
  
  AUTH = my_little_auth
  
  COUNTRIES = YAML::load(File.read(File.dirname(PATH) + '/pasaporte/iso_countries.yml')) #:nodoc:
  TIMEZONES = YAML::load(File.read(File.dirname(PATH) + '/pasaporte/timezones.yml')).sort{|e1, e2| e1[1] <=> e2[1]} #:nodoc:
  
  DOCTYPE = %[<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">] #:nodoc:
    
  # Reads and applies pasaporte/config.yml to the constants
  def self.apply_config!
     silence_warnings do
      begin
        fc = File.read(File.dirname(PATH) + '/pasaporte/config.yml')
        YAML::load(fc).each_pair do |k, v|
          # Cause us to fail if this constant does not exist
          norm = k.to_s.upcase.to_sym
          const_get(norm); const_set(norm, v)
        end
      rescue Errno::ENOENT # silence
      end
    end
  end

  # Adds a magicvar that gets cleansed akin to Rails Flash
  module CampingFlash
    def service(*a)
      expire= (@state && @state.msg)
      returning(super(*a)) do
        # Expire the message if it was there before the action
        @state.delete('msg') if (@state && expire)
      end
    end
  end
  
  # Or a semblance thereof
  module Secure
    class PleaseLogin < RuntimeError; end
    class Throttled < RuntimeError; end
    class FullStop < RuntimeError; end
    
    module CheckMethods
      def _redir_to_login_page!(persistables)
        @state.merge!(persistables)
        # Prevent Camping from munging our URI with the mountpoint
        @state.msg ||= "First you will need to login"
        LOGGER.info "Suspending #{@nickname} until he is logged in"
        raise PleaseLogin
      end
      
      # Allow the user to log in. Suspend any variables passed in the session.
      def require_login(persistables = {})
        deny_throttled!
        raise "No nickname" unless @nickname
        _redir_to_login_page!(persistables) unless is_logged_in?
        @profile = profile_by_nickname(@nickname)
        @title = "%s's pasaporte" % @nickname
      end
      
      # Deny throttled users any action
      def deny_throttled!
        raise Throttled if Models::Throttle.throttled?(env)
      end
    
      def profile_by_nickname(n)
        ::Pasaporte::Models::Profile.find_or_create_by_nickname_and_domain_name(n, my_domain)
      end
    end
    
    def expire_old_sessions!
      day_zero = (Time.now - SESSION_LIFETIME).to_s(:db)
      Camping::Models::Session.delete_all("created_at < '%s'" % day_zero)
    end
    
    def service(*a)
      begin
        expire_old_sessions!
        @ctr = self.class.to_s.split('::').pop
        super(*a)
      rescue FullStop
        return self
      rescue PleaseLogin
        # This bypasses a session generation bug - http://code.whytheluckystiff.net/camping/ticket/143
        @headers['Set-Cookie'] = 'camping_sid=%s; path=/' % @cookies.camping_sid 
        redirect R(Pasaporte::Controllers::Signon, @nickname)
        return self
      rescue Throttled
        LOGGER.info "#{env['REMOTE_ADDR']} - Throttled user tried again"
        redirect R(Pasaporte::Controllers::ThrottledPage)
        return self
      end
      self
    end
  end

  # Adds a DOCTYPE to all outgoing HTML - a Camping bug.
  module Proper #:nodoc:
    def service(*a)
      returning(super(*a)) do | r |
        r.body = (DOCTYPE + "\n" + r.body) if (r.headers["Content-type"] == "text/html")
      end
    end
  end

  # The order here is important. Camping::Session has to come LAST (innermost)
  # otherwise you risk losing the session if one of the services upstream
  # redirects.
  [CampingFlash, Secure, Camping::Session].map{|m| include m }

  module Models
    
    class CreatePasaporte < V 1.0
      def self.up
        create_table :pasaporte_profiles, :force => true do |t|
          # http://openid.net/specs/openid-simple-registration-extension-1_0.html
          t.column :nickname, :string, :maxlength => 20
          t.column :email, :string, :maxlength => 70
          t.column :fullname, :string, :maxlength => 50
          t.column :dob, :date, :null => true
          t.column :gender, :string, :maxlength => 1
          t.column :postcode, :string, :maxlength => 10
          t.column :country, :string, :maxlength => 2
          t.column :language, :string, :maxlength => 5
          t.column :timezone, :string, :maxlength => 50
  
          # And our extensions
          # is the profile shared (visible to others)
          t.column :shared, :boolean, :default => false
  
          # his bio
          t.column :info, :text
  
          # when he last used Pasaporte
          t.column :last_login, :datetime
  
          # the encryption part that we generate for every user, the other is the pass
          # the total encryption key for private data will be stored in the session only when
          # the user is logged in
          t.column :secret_salt, :integer
  
          # Good servers delegate
          t.column :openid_server, :string
          t.column :openid_delegate, :string
  
          # We shard by domain
          t.column :domain_name, :string, :null => false, :default => 'localhost'
  
          # Keep a close watch on those who
          t.column :throttle_count, :integer, :default => 0
          t.column :suspicious, :boolean, :default => false
        end
  
        add_index(:pasaporte_profiles, [:nickname, :domain_name], :unique)
  
        create_table :pasaporte_settings do |t|
          t.column :setting, :string
          t.column :value, :binary
        end
  
        create_table :pasaporte_associations do |t|
          # server_url is blob, because URLs could be longer
          # than db can handle as a string
          t.column :server_url, :binary
          t.column :handle,     :string
          t.column :secret,     :binary
          t.column :issued,     :integer
          t.column :lifetime,   :integer
          t.column :assoc_type, :string
        end
  
        create_table :pasaporte_nonces do |t|
          t.column :nonce,   :string
          t.column :created, :integer
        end
  
        create_table :pasaporte_throttles do |t|
          t.column :created_at, :datetime
          t.column :client_fingerprint, :string, :maxlength => 40
        end
      end
  
      def self.down
        drop_table :pasaporte_profiles
        drop_table :pasaporte_settings
        drop_table :pasaporte_associations
        drop_table :pasaporte_nonces
        drop_table :pasaporte_throttles
      end
    end
    class AddAprovals < V(1.1)
      def self.up
        create_table :pasaporte_approvals do | t |
          t.column :profile_id, :integer, :null => false
          t.column :trust_root, :string, :null => false
        end
        add_index(:pasaporte_approvals, [:profile_id, :trust_root], :unique)
      end
  
      def self.down
        drop_table :pasaporte_approvals
      end
    end
  
    # Minimal info we store about people. It's the container for the sreg data
    # in the first place.
    class Profile < Base
      before_create { |p| p.secret_salt = rand(Time.now) }
      before_save :validate_delegate_uris
      validates_presence_of :nickname
      validates_presence_of :domain_name
      validates_uniqueness_of :nickname, :scope => :domain_name
      attr_protected :domain_name, :nickname
      has_many :approvals, :dependent => :delete_all
  
      any_url_present = lambda do |r| 
        !r.openid_server.blank? || !r.openid_server.blank?
      end
      %w(openid_server openid_delegate).map do | c |
        validates_presence_of c, :if => any_url_present
      end
  
      attr_writer :delegates_openid # dummy for forms
  
      # Convert the profile to sreg according to the spec (YYYY-MM-DD for dob and such)
      def to_sreg_fields(fields_to_extract = nil)
        fields_to_extract ||= %w( nickname email fullname dob gender postcode country language timezone )
        fields_to_extract.inject({}) do | out, field |
          v = self[field]
          v.blank? ? out : (out[field.to_s] = v.to_s; out)
        end
      end
  
      # We have to override that because we want our protected attributes
      def self.find_or_create_by_nickname_and_domain_name(nick, domain)
        returning(super(nick, domain)) do | me |
          ((me.nickname, me.domain_name = nick, domain) && me.save) if me.new_record?
        end
      end
      class << self
        alias_method :find_or_create_by_domain_name_and_nickname,
        :find_or_create_by_nickname_and_domain_name
      end
      
      def generate_sess_key
        self.secret_salt ||= rand(Time.now)
        s = [nickname, secret_salt, Time.now.year, Time.now.month].join('|')
        OpenSSL::Digest::SHA1.new(s).hexdigest.to_s
      end
  
      # Check if this profile wants us to delegate his openid to a different identity provider.
      # If both delegate and server are filled in properly this will return true
      def delegates_openid?
        ALLOW_DELEGATION && (!openid_server.blank? && !openid_delegate.blank?)
      end
      alias_method :delegates_openid, :delegates_openid? # for checkboxes
  
      private
      def validate_delegate_uris
        if ([self.openid_server, self.openid_delegate].select{|i| i.blank?}).length == 1
          errors.add(:delegate_server, "If you use delegation you have to specify both addresses")
          false
        end
  
        %w(openid_server openid_delegate).map do | attr |
          return if self[attr].blank?
          flattened = OpenID::URINorm.urinorm(self[attr])
          self[attr] = (flattened || (errors.add(attr, 'Only HTTP protocol addresses can be used'); self[attr]))
        end
      end
    end
   
    # A token that the user has approved a site (a site's trust root) as legal
    # recipient of his information
    class Approval < Base
      belongs_to :profile
      validates_presence_of :profile_id, :trust_root
      validates_uniqueness_of :trust_root, :scope => :profile_id
      def to_s; trust_root; end
    end
    
    # Openid setting
    class Setting < Base; end
    
    # Openid nonces
    class Nonce < Base; end
    
    # Openid assocs
    class Association < Base
      def from_record
        OpenID::Association.new(handle, secret, issued, lifetime, assoc_type)
      end
      
      def expired?
        Time.now.to_i > (issued + lifetime)
      end
    end
   
    # Set throttles
    class Throttle < Base
    
      # Set a throttle with the environment of the request
      def self.set!(e)
        create(:client_fingerprint => env_hash(e))
      end
    
      # Check if an environment is throttled
      def self.throttled?(e)
        prune!
        count(:conditions => ["client_fingerprint = ? AND created_at > ?", env_hash(e), cutoff]) > 0
      end
    
      private
      def self.prune!;  delete_all "created_at < '#{cutoff.to_s(:db)}'"; end
      def self.cutoff; Time.now - THROTTLE_FOR; end
      def self.env_hash(e)
        OpenSSL::Digest::SHA1.new([e['REMOTE_ADDR'], e['HTTP_USER_AGENT']].map(&:to_s).join('|')).to_s
      end
    end
  end
   
  require File.dirname(__FILE__) + '/pasaporte/pasaporte_store'
  
  module Controllers
    
    # Wraps the "get" and "post" with nickname passed in the path. When
    # get_with_nick is called, @nickname is already there.
    module Nicknames
      def get(*extras)
        raise "Nickname is required for this action" unless (@nickname = extras.shift)
        get_with_nick(*extras)
      end
      
      def post(*extras)
        raise "Nickname is required for this action" unless (@nickname = extras.shift)
        post_with_nick(*extras)
      end
      def respond_to?(m, *whatever)
        super(m.to_sym) || super("#{m}_with_nick".to_sym)
      end
    end
    
    # Make a controller for a specfic user
    def self.personal(uri = nil)
      returning(R(["/([^\/]+)", uri].compact.map{|e| e.to_s}.join("/"))) do | ak |
        ak.send(:include, Secure::CheckMethods)
        ak.send(:include, Nicknames)
      end
    end
  
    # Performs the actual OpenID tasks. POST is for the
    # requesting party, GET is for the browser
    class Openid < personal(:openid)
      include OpenID::Server
      
      class Err < RuntimeError; end #:nodoc
      class NeedsApproval < RuntimeError; end  #:nodoc
      class Denied < Err; end  #:nodoc
      class NoOpenidRequest < RuntimeError; end  #:nodoc
      
      def get_with_nick
        # Force a session save
        @state.touched = Time.now.to_i
        begin
          @oid_request = openid_request_from_input_or_session
          
          LOGGER.info "pasaporte: user #{@nickname} must not be throttled"
          deny_throttled!
          
          LOGGER.info "pasaporte: nick must match the identity URL"
          check_nickname_matches_identity_url
          
          LOGGER.info "pasaporte: user must be logged in"
          check_logged_in
          
          @profile = profile_by_nickname(@nickname)
          
          LOGGER.info "pasaporte: trust root is on the approvals list"
          check_if_previously_approved
          
          LOGGER.info "pasaporte: OpenID verified, redirecting"
          
          succesful_resp = @oid_request.answer(true)
          add_sreg(@oid_request, succesful_resp)
          send_openid_response(succesful_resp)
        rescue NoOpenidRequest
          return 'This is an OpenID server endpoint.'
        rescue ProtocolError => e
          LOGGER.error "pasaporte: Cannot decode the OpenID request - #{e.message}"
          return "Something went wrong processing your request"
        rescue PleaseLogin => e
          # There is a subtlety here. If the user had NO session before entering
          # this, he will get a new SID upon arriving at the signon page and thus
          # will loose his openid request.
          @oid_request.immediate ? ask_user_to_approve : (raise e)
        rescue NeedsApproval
          LOGGER.warn "pasaporte: suspend - the URL needs approval first"
          ask_user_to_approve
        rescue Denied => d
          LOGGER.warn "pasaporte: deny OpenID to #{@nickname} - #{d.message}"
          send_openid_response(@oid_request.answer(false))
        rescue Secure::Throttled => e
          LOGGER.warn "pasaporte: deny OpenID to #{@nickname} - user is throttled"
          send_openid_response(@oid_request.answer(false))
        end
      end
  
      def post_with_nick
        req = openid_server.decode_request(input)
        # Check for dumb mode HIER!
        resp = openid_server.handle_request(req)
        # we need to preserve the session on POST actions
        send_openid_response(resp, true)
      end
  
      private
      
      def openid_request_from_input_or_session
        if input.keys.grep(/openid/).any?
          @state.delete(:pending_openid)
          r = openid_server.decode_request(input)
          LOGGER.info "Starting a new OpenID session with #{r.trust_root}"
          @state.pending_openid = r
        elsif @state.pending_openid
          LOGGER.info "Resuming an OpenID session with #{@state.pending_openid.trust_root}"
          @state.pending_openid
        else
          raise NoOpenidRequest
        end
      end
      
      # FIXME - the claimed ID that comes in is somehow empty
      def check_nickname_matches_identity_url
        nick_from_uri = @oid_request.identity.to_s.split(/\//)[-2]
        if (nick_from_uri != @nickname)
          raise Denied, "The identity '#{@oid_request.claimed_id}' does not mach the URL realm"
        end
  
        if (@state.nickname && (nick_from_uri != @state.nickname))
          raise Denied, "The identity '#{@oid_request.identity_url}' is not the one of the current user"
        end
      end
  
      def check_logged_in
        message = "Before authorizing '%s' you will need to login" % input["openid.trust_root"]
        require_login(:pending_openid => @oid_request, :msg => message)
      end
      
      def ask_user_to_approve
        @state.pending_openid = @oid_request
        if @oid_request.immediate
          absolutized_signon_url = unless is_logged_in?
            File.dirname(_our_endpoint_uri) + '/signon'
          else
            File.dirname(_our_endpoint_uri) + '/decide'
          end
          LOGGER.info "Will need to ask the remote to setup at #{absolutized_signon_url}"
          resp = @oid_request.answer(false, absolutized_signon_url)
          send_openid_response(resp, true); return
        else
          redirect R(Decide, @nickname)
        end
      end
      
      # This has to be fixed. By default, we answer _false_ to immediate mode
      # if we need the user to sign in or do other tasks, this is important 
      def check_if_previously_approved
        unless @profile.approvals.find_by_trust_root(@oid_request.trust_root)
          raise NeedsApproval.new(@oid_request)
        end
      end
    end
    
    # Return the yadis autodiscovery XML for the user
    class Yadis < personal(:yadis)
      def get_with_nick
        @headers["Content-type"] = "application/xrds+xml"
        @skip_layout = true
        return '<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)" xmlns:openid="http://openid.net/xmlns/1.0">
        <XRD>
        <Service priority="1">
        <Type>http://openid.net/signon/1.0</Type>
        <URI>%s</URI>
        <openid:Delegate>%s</openid:Delegate>
        </Service>
        </XRD>
        </xrds:XRDS>' % get_endpoints
        
      end
      private
        def get_endpoints
          defaults = [_our_endpoint_uri]*2
          @profile = Profile.find_by_nickname_and_domain_name(@nickname, my_domain)
          return defaults unless @profile && @profile.delegates_openid?
          [@profile.openid_server, @profile.openid_delegate]
        end
    end
    
    class ApprovalsPage < personal(:approvals)
      def get_with_nick
        require_login
        @approvals = @profile.approvals
        render :approvals_page
      end
    end

    class DeleteApproval < personal("disapprove/(\d+)")
      def get_with_nick(id)
        @nickname = nick
        require_login
        @profile.approvals.destroy(id)
        redirect R(ApprovalsPage, @nickname)
      end
      alias_method :post_with_nick, :get_with_nick
    end
    
    # Shows a signon page that allows to enter the login
    class PublicSignon < R('/')
      def get
        render :signon_form
      end
      
      def post
        # encode the input and forward it to the private login page
        y = Pasaporte.post(:Signon, input.login, {"env"=>env, "input" => input})
        if y.status == 302
          @status, @headers['Location'] = 302, y.headers['Location']; return
        end
        # r does not work quite well for redirects (well it kinda does but not always)
        r(y.status, y.body, y.headers)
      end
    end
    
    # Show the login form and accept the input
    class Signon < personal(:signon)
      
      def get_with_nick
        deny_throttled!
        if @state.pending_openid
          humane = URI.parse(@state.pending_openid.trust_root).host
          @msg = "Before authorizing with <b>#{humane}</b> you will need to login"
        end
        render :signon_form
      end
      
      def post_with_nick
        begin
          deny_throttled!
        rescue Pasaporte::Secure::Throttled => th
          if @state.pending_openid
            buggeroff = @state.delete(:pending_openid).answer(false)
            send_openid_response(buggeroff); return
          end
          raise th
        end
        
        # The throttling logic must be moved into throttles apparently
        # Start counting
        @state.failed_logins ||= 0
        
        # If the user reaches the failed login limit we ban him for a while and
        # tell the OpenID requesting party to go away
        if Pasaporte::AUTH.call(@nickname, input.pass, my_domain)
          # Special case - if the login ultimately differs from the one entered
          # we need to take care of that and tell the OID consumer that we want to restart
          # from a different profile URL
          @state.nickname = @nickname
          @profile = profile_by_nickname(@nickname)
          
          # Recet the grace counter
          @state.failed_logins = 0
          
          # Enforce a cookie 
          @headers['Set-Cookie'] = 'camping_sid=%s; path=/' % @cookies.camping_sid 

          # If we have a suspended OpenID procedure going on - continue
          redirect R((@state.pending_openid ? Openid : ProfileEditor), @nickname); return
        else
          @msg = "Oops.. cannot find you there"
          # Raise the grace counter
          @state.failed_logins += 1
          if @state.failed_logins >= MAX_FAILED_LOGIN_ATTEMPTS
            LOGGER.info("%s - failed %s times, taking action" %  
              [@nickname, MAX_FAILED_LOGIN_ATTEMPTS])
            punish_the_violator
          else
            @state.delete(:nickname)
            render :signon_form
          end
        end
      end
      private
      def punish_the_violator
        @report = "I am stopping you from sending logins for some time so that you can " +
        "lookup (or remember) your password. See you later."
        Throttle.set!(env)
  
        @state.failed_logins = 0
        LOGGER.info "#{env['REMOTE_ADDR']} - Throttling #{@nickname}"
  
        # If we still have an OpenID request hanging about we need
        # to let the remote party know that there is nothing left to hope for
        if @state.pending_openid
          # Mark the profile as suspicious - failed logins mean that maybe he delegated everything
          # but is no longer listed on the backend
          if p = profile_by_nickname(@nickname)
            p.update_attributes :suspicious => true, :throttle_count => (p.throttle_count + 1)
            if p.throttle_count > 3
              LOGGER.error "#{@nickname}@#{my_domain} has been throttled 3 times but is still trying hard"
            end
          end
          # Reset the state so that the session is regenerated. Something wrong is
          # going on so we better be sure
          @oid_request = @state.delete(:pending_openid)
          #@state = {}
          # And send the flowers away
          bugger_off = @oid_request.answer(false)
          return send_openid_response(bugger_off)
        else
          render :bailout
        end
      end
    end
    
    # Logout the user, remove associations and session
    class Signout < personal(:signout)
      def get_with_nick
        (redirect R(Signon, @nickname); return) unless is_logged_in?
        # reset the session in our part only
        @state = Camping::H.new
        @state.msg = "Thanks for using the service and goodbye"
        redirect R(Signon, @nickname)
      end
    end
    
    # Figure out if we want to pass info to a site or not. This gets called
    # when associating for the first time
    class Decide < personal(:decide)
      def get_with_nick
        require_login
        @oid_request = @state.pending_openid
        render :decide
      end
      
      def post_with_nick
        require_login
        if !@state.pending_openid
          @report = "There is no more OpenID request to approve. Looks like it went out already."
          render :bailout
        elsif input.nope
          @oid_request = @state.delete(:pending_openid)
          send_openid_response @oid_request.answer(false); return
        else
          @profile.approvals.create(:trust_root => @state.pending_openid.trust_root)
          redirect R(Openid, @nickname); return
        end
      end
    end
    
    # Allows the user to modify the settings
    class ProfileEditor < personal(:edit)
      def get_with_nick
        require_login
        render :profile_form
      end
      
      def post_with_nick
        require_login
        _collapse_checkbox_input(input)
        
        if @profile.update_attributes(input.profile)
          @msg = "Your settings have been changed"
        else
          @err = "Cannot save your profile: <b>%s</b>" % @profile.errors.full_messages
        end
        
        render :profile_form
      end
    end
  
    # Catchall for static files, with some caching support
    class Assets < R('/assets/(.+)')
      MIME_TYPES = {
        'html' => 'text/html', 'css' => 'text/css', 'js' => 'text/javascript', 
        'jpg' => 'image/jpeg', 'gif' => 'image/gif', 'png' => 'image/png'
      }
      ASSETS = File.join File.dirname(Pasaporte::PATH), 'pasaporte/assets/'
  
      def get(path)
        if env["HTTP_IF_MODIFIED_SINCE"]
          @status = 304
          return 'Not Modified'
        end
  
        # Squeeze out all possible directory traversals
        path = File.join ASSETS, path.gsub(/\.\./, '').gsub(/\s/, '')
        path.squeeze!('/')
        
        # Somehow determine if we support sendfile, because sometimes we dont
        if File.exist?(path)
          ext = File.extname(path).gsub(/^\./, '')
          magic_headers = {
            'Last-Modified' => 2.days.ago.to_s(:http),
            'Expires' => 30.days.from_now.to_s(:http),
            'Cache-Control' => "public; max-age=#{360.hours}",
            'Last-Modified' => 2.hours.ago.to_s(:http),
          }
          @headers.merge!(magic_headers)
          @headers['Content-Type'] = MIME_TYPES[ext] || "text/plain"
          @headers['X-Sendfile'] = path
        else
          @status = 404
          self << "No such item"
        end
      end
    end
  
    # This gets shown if the user is throttled
    class ThrottledPage < R('/you-have-been-throttled')
      def get
        @report = "You have been throttled for #{THROTTLE_FOR} seconds"
        render :bailout
      end
    end
  
    # Just show a public profile page. Before the user logs in for the first time
    # it works like a dummy page. After the user has been succesfully authenticated he can
    # show his personal info on this page (this is his identity URL).
    class ProfilePage < personal
      def get(nick)
        @nickname = nick
        @headers['X-XRDS-Location'] = _our_identity_url + '/yadis'
        @title = "#{@nickname}'s profile" 
        @profile = Profile.find_by_nickname_and_domain_name(@nickname, my_domain)
        @no_toolbar = true
        render(@profile && @profile.shared? ? :profile_public_page : :endpoint_splash)
      end
    end
  end

  module Helpers
  
    def is_logged_in?
      (@state.nickname && (@state.nickname == @nickname))
    end
    
    # Return a RELATIVELY reliable domain key
    def my_domain
      env["SERVER_NAME"].gsub(/^www\./i, '').chars.downcase.to_s
    end
  
    # Camping processes double values (hidden field with 0 and checkbox with 1) as an array.
    # This collapses the ["0","1"] array to a single value of "1"
    def _collapse_checkbox_input(ha)
      ha.each_pair do | k,v |
        (v == ["0", "1"]) ? (ha[k] = "1") : (v.is_a?(Hash) ? _collapse_checkbox_input(v) : true)
      end
    end
  
    def openid_server
      @store ||= PasaporteStore.new
      # we also need to provide endopint URL - this is where Pasaporte is mounted
      @server ||= OpenID::Server::Server.new(@store, @env['SERVER_NAME'])
      @server
    end
  
    # Add sreg details from Mai Profail to the response
    def add_sreg(request, response)
      # The user should be able to approve the transfer
      # and modify each field if she likes.
      when_sreg_is_required(request) do | fields, policy_url |
        response.add_fields('sreg', @profile.to_sreg_fields(fields))
      end
    end
  
    def when_sreg_is_required(openid_request)
      required = openid_request.query['openid.sreg.required']
      optional = openid_request.query['openid.sreg.optional']
      policy_url = openid_request.query['openid.sreg.policy_url']
  
      something_needed = required || optional || policy_url
      if block_given? && something_needed
        yield(required.split(',') + optional.split(','), policy_url)
      else
        something_needed
      end
    end
  
    # Convert from the absurd response object to something Camping can fret
    # The second argument determines if the session needs to be cleared as well
    def send_openid_response(oid_resp, keep_in_session = false)
      web_response = openid_server.encode_response(oid_resp)
      @state.delete(:pending_openid) unless keep_in_session
      case web_response.code
        when OpenID::Server::HTTP_OK
          @body = web_response.body           
        when OpenID::Server::HTTP_REDIRECT
          redirect web_response.headers['location']
        else # This is a 400 response, we do not support something
          @status, @body = 400, web_response.body
      end
    end
  
    def _todo(msg=nil)
      # LOGGER.error " "
      # LOGGER.error("FIXME! - %s" % msg)
      # LOGGER.info caller[0..2].join("\n")  
      if self.respond_to?(:div) 
        div(:style=>'color:red;font-size:1.1em'){"TODO!"}
      end
    end
  end
  
  module Views

    # Harsh but necessary
    def bailout
      h2 "Sorry but it's true"
      self << p(@report)
    end

    # Render the public profile page
    def profile_public_page
      h2 do
        _h(@profile.fullname.blank? ? @profile.nickname : @profile.fullname)
      end
      p _h(@profile.info)
    end

    def signon_form
      
      form.signon! :method => :post do
        label :for => 'login' do
          self << "Your name:"
          # We include a hidden input here but it's only ever used by PublicSignon
          if @nickname
            b(@nickname)
            input(:name => "login", :value => @nickname, :type => :hidden)
          else
            input.login!(:name => "login", :value => @nickname)
          end
        end
        label :for => 'pass' do
          self << "Your password:"
          input.pass! :name => "pass", :type => "password"
        end
        input :type => :submit, :value => 'Log me in'
      end
    end

    def layout
      @headers['Cache-Control'] = 'no-cache; must-revalidate'
      if @skip_layout
        self << yield
        return
      end

      @headers['Content-type'] = 'text/html'
      xhtml_transitional do
        head do
          link :rel => "openid.server", :href => _openid_server_uri 
          link :rel => "openid.delegate", :href => _openid_delegate_uri
          link :rel => "stylesheet", :href => _s("pasaporte.css")
          script :type=>'text/javascript', :src => _s("pasaporte.js")
          title(@title || ('%s : pasaporte' % env['SERVER_NAME']))
        end
        body :class => @ctr do
          unless @no_toolbar
            div.toolbar! do
              if is_logged_in?
                a.loginBtn! "Log out", :href => R(Signout, @nickname)
                b.profBtn! @nickname.capitalize
              else
                b.loginBtn! "You are not logged in"
              end
              img :src => R(Assets, '/openid.png'), :alt => 'OpenID system'
            end
          end
          
          div.work! :class => (is_logged_in? ? "logdin" : "notAuth") do
            returning(@err || @msg || @state.msg) {| m | div.msg!{m} if m } 
            self << yield
          end
        end
      end
    end

    # link to a static file
    def _s(file)
      R(Assets, file)
    end
    
    # Render either our server URL or the URL of the delegate
    def _openid_server_uri
      (@profile && @profile.delegates_openid?) ? @profile.openid_server : _our_endpoint_uri
    end

    # Render either our providing URL or the URL of the delegate    
    def _openid_delegate_uri
      (@profile && @profile.delegates_openid?) ? @profile.openid_delegate : _our_endpoint_uri
    end

    # Canonicalized URL of our endpoint    
    def _our_endpoint_uri
      uri = "http://" + [env["HTTP_HOST"], env["SCRIPT_NAME"], R(Openid, @nickname)].join('/').squeeze('/')
      OpenID::URINorm.urinorm(uri)
    end
    
    def _our_identity_url
      uri = "http://" + [env["HTTP_HOST"], env["SCRIPT_NAME"], R(ProfilePage, @nickname)].join('/').squeeze('/')
      OpenID::URINorm.urinorm(uri)
    end

    # HTML esc. snatched off ERB
    def _h(s)
      s.to_s.gsub(/&/, "&amp;").gsub(/\"/, "&quot;").gsub(/>/, "&gt;").gsub(/</, "&lt;")
    end

    # Let the user decide what data he wants to transfer
    def decide
      h2{ "Please approve <b>#{_h(@oid_request.trust_root)}</b>" }
      p  "You never logged into that site with us. Do you want us to approve? "

      when_sreg_is_required(@oid_request) do | asked_fields, policy |
        fields = asked_fields.to_sentence
        p{"Additionally, the site wants to know your <b>#{fields}.</b> These will be sent along."}
        if policy
          p do 
            self << "That site has a "
            a("policy on it's handling of user data", :href => policy_url)
            self << " that you might want to read beforehand."
          end
        end
      end

      form :method => :post do
        input :name => :pleasedo, :type => :submit, :value => " Yes, do allow "
        self << '&#160;'
        input :name => :nope, :type => :submit, :value => " No, they are villains! "
      end
    end

    def _toolbar
      # my profile button
      # log me out button
    end

    def approvals_page
      h2 { "Hello " + b(@profile) }
      p do
        self << "You are now logged in. Pass the following address to any OpenID-enabled site that you want to visit"
        b _our_identity_url
      end
      if @approvals.any?
        h2 "The sites you trust"
        p { small "These sites will be able to automatically log you in without first asking you to approve"}
        ul do
          @approvals.map do | approval |
            li { approval }
          end
        end
      end
    end
    
    def _tf(obj_name, field, t, opts = {})
      obj, field_name, id = instance_variable_get("@#{obj_name}"), "#{obj_name}[#{field}]", "#{obj_name}_#{field}"
      label.fb(:for => id) do
        self << t
        input opts.merge(:type => "text", :value => obj[field], :id => id, :name => field_name)
      end
    end

    def _cbox(obj_name, field, opts = {})
      obj, field_name = instance_variable_get("@#{obj_name}"), "#{obj_name}[#{field}]"
      input :type=>:hidden, :name => field_name, :value => 0

      opts[:id] ||= "#{obj_name}_#{field}"
      if !!obj.send(field)
        input opts.merge(:type=>:checkbox, :name => field_name, :value => 1, :checked => :checked)
      else
        input opts.merge(:type=>:checkbox, :name => field_name, :value => 1)
      end
    end

    def profile_form
      form(:method => :post) do
        
        h2 "Your profile"
        
        label.cblabel :for => :share_info do
          _cbox :profile, :shared, :id => :share_info 
          self << '&#160; Share your info on your OpenID page'
          self << " ("
          b { a(:href => _profile_url, :target => '_new') { _profile_url } }
          self << ")"
        end

        div.persinfo! :style => "display: #{@profile.shared? ? 'block' : 'none'}" do
          textarea(:rows => 10, :name => 'profile[info]') { @profile.info }
        end

        script(:type=>"text/javascript") do
          self << %Q[ attachCheckbox("share_info", "persinfo");]
        end

        h2 "Simple registration info"
        p.sml 'When you register on some sites they can ' +
        'use this info to fill their registration forms ' +
        'for you'

        _tf(:profile, :fullname, "Your full name:")
        _tf(:profile, :email, "Your e-mail:")

        div.rad do
          self << "You are &#160;"
          {'m' => '&#160;a guy&#160;', 'f' => '&#160;a gal&#160;'}.each_pair do | v, t |
            opts = {:id => "gend_#{v}", :type=>:radio, :name => 'profile[gender]', :value => v}
            opts[:checked] = :checked if @profile.gender == v
            label(:for => opts[:id]) { input(opts); self << t }
          end
        end

        label.sel(:for => 'countries') do
          self << "Your country of residence"
          select :id=>:countries, :name => 'profile[country]' do
           COUNTRIES.values.sort.map do | c |
             code = COUNTRIES.index(c)
             opts = {:value => code}
             if (@profile.country && @profile.country == code) || DEFAULT_COUNTRY == code
               opts[:selected] = true
             end
             option(opts) { c } 
           end
          end
        end

        label.sel do
          self << "Your date of birth" 
          _todo
        end

        label "The timezone you are in"
        select :name => 'profile[timezone]', :style => 'width: 100%' do
          TIMEZONES.map do | formal, humane |
            opts = {:value => formal}
            opts.merge! :selected => :selected if (formal == @profile.timezone)
            option(humane, opts)
          end
        end

        if ALLOW_DELEGATION
          h2 "OpenID delegation"
          label.cblabel :for => :delegate do 
            _cbox(:profile, :delegates_openid)
            self << "&#160; Use another site " +
            "as your <a href='http://openid.net/wiki/index.php/Delegation'>OpenID provider.</a>"
          end

          div.smaller :id => 'delegationDetails' do
            p "The site that you want to use for OpenID should have given you the necessary URLs."
            _tf(:profile, :openid_server, "Server URL:")
            _tf(:profile, :openid_delegate, "Delegate URL:")
          end
        end

        script(:type=>"text/javascript") do
          self << %Q[ attachCheckbox("profile_delegates_openid", "delegationDetails");]
        end

        hr
        input :type=>:submit, :value=>'Save my settings' # or Cancel
      end
    end

    # Canonicalized identity URL of the current profile
    def _profile_url
      "http://" + [env["HTTP_HOST"], env["SCRIPT_NAME"], @profile.nickname].join('/').squeeze('/')
    end

    # A dummy page that gets shown if the user hides his profile info
    # or he hasn't authenticated with us yet
    def endpoint_splash
      h3 { "This is <b>#{@nickname}'s</b> page" }
    end
  end

  def self.create
    ::Camping::Models::Session.create_schema
    self::Models.create_schema
  end
end