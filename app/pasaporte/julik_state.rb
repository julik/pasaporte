# Camping session module is a wretched piece of junk, so we just replace it
module JulikState
  require 'activerecord'
  class State < ActiveRecord::Base; set_table_name 'julik_states'; serialize :blob; end
  
  def self.create_schema
    return if State.table_exists?
    ActiveRecord::Schema.define do
      create_table :julik_states do | s |
        s.column :blob, :text
        s.column :sid, :string, :limit => 32
        s.column :app, :string, :null => false, :limit => 50
        s.column :modified_at, :datetime
        s.column :created_at, :datetime
      end
      add_index :julik_states, [:sid, :app], :unique => true
      State.reset_column_information
    end
  end
  RC = [*'A'..'Z'] + [*'0'..'9'] + [*'a'..'z']
  def _sid; (0...32).inject("") { |ret,_| ret << RC[rand(RC.length)] }; end
  def _appn; self.class.to_s.split(/::/).shift; end
  
  # Generate a HMAC signature based on the session key and a few key HTTP request
  # headers
  def _generate_digest(key, header_hash)
    fingerprint = [key, header_hash['HTTP_USER_AGENT'], header_hash['REMOTE_IP'] || header_hash['REMOTE_ADDR']]
    enc = Base64.encode64(Marshal.dump(fingerprint))
    digest_type = 'SHA1'
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new(digest_type), secret, enc)
  end
  
  def service(*a)
    fresh = Camping::H[{}]
    s = State.find_by_sid_and_app(@cookies.jsid, _appn) || State.new(:app => _appn, :blob => fresh,
      :sid => (@cookies.jsid ||= _sid))
    @state = s.blob.dup
    @msg = @state.delete(:msg)
    returning(super(*a)) do
      s.update_attributes :blob => @state if (@state != s.blob)
    end
  end
end