module Pasaporte::Models
  MAX = :limit # Thank you rails core, it was MAX before
  class CreatePasaporte < V 1.0
    def self.up
      create_table :pasaporte_profiles, :force => true do |t|
        # http://openid.net/specs/openid-simple-registration-extension-1_0.html
        t.column :nickname, :string, MAX => 20
        t.column :email, :string, MAX => 70
        t.column :fullname, :string, MAX => 50
        t.column :dob, :date, :null => true
        t.column :gender, :string, MAX => 1
        t.column :postcode, :string, MAX => 10
        t.column :country, :string, MAX => 2
        t.column :language, :string, MAX => 5
        t.column :timezone, :string, MAX => 50

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
        t.column :client_fingerprint, :string, MAX => 40
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
  
  class MigrateOpenidTables < V(1.2)
    def self.up
      drop_table :pasaporte_settings
      drop_table :pasaporte_nonces
      create_table :pasaporte_nonces, :force => true do |t|
        t.column :server_url, :string, :null => false
        t.column :timestamp, :integer, :null => false
        t.column :salt, :string, :null => false
      end
    end
    
    def self.down
      drop_table :pasaporte_nonces
      create_table :pasaporte_nonces, :force => true do |t|
        t.column "nonce", :string
        t.column "created", :integer
      end
      
      create_table :pasaporte_settings, :force => true do |t|
        t.column "setting", :string
        t.column "value", :binary
      end
    end
  end
  
  class ShardOpenidTables < V(1.3)
    def self.up
      add_column :pasaporte_associations, :pasaporte_domain, :string, :null => false, :default => 'localhost'
      add_column :pasaporte_nonces, :pasaporte_domain, :string, :null => false, :default => 'localhost'
    end
    
    def self.down
      remove_column :pasaporte_nonces, :pasaporte_domain
      remove_column :pasaporte_associations, :pasaporte_domain
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
      Pasaporte::ALLOW_DELEGATION && (!openid_server.blank? && !openid_delegate.blank?)
    end
    
    def delegates_openid=(nv)
      (self.openid_server, self.openid_delegate = nil, nil) if [false, '0', 0, 'no'].include?(nv) 
    end
    alias_method :delegates_openid, :delegates_openid? # for checkboxes
    
    def to_s; nickname; end
    
    private
    def validate_delegate_uris
      if ([self.openid_server, self.openid_delegate].select{|i| i.blank?}).length == 1
        errors.add(:delegate_server, "If you use delegation you have to specify both addresses")
        false
      end
      
      %w(openid_server openid_delegate).map do | attr |
        return if self[attr].blank?
        begin
          self[attr] = OpenID::URINorm.urinorm(self[attr])
        rescue Exception => e
          errors.add(attr, e.message)
        end
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
end # Pasaporte::Models