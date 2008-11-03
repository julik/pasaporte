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
  
  def force_session_save!
    @cookies.jsid ||= _sid
    res = @js_rec.update_attributes :blob => @state, :sid => @cookies.jsid
    raise "Cannot save session" unless res
  end
  
  def service(*a)
    
    fresh = Camping::H[{}]
    @js_rec = State.find_by_sid_and_app(@cookies.jsid, _appn) || State.new(:app => _appn, :blob => fresh,
      :sid => (@cookies.jsid ||= _sid))
    
    @state = @js_rec.blob.dup
    @msg = @state.delete(:msg)
    returning(super(*a)) do
      force_session_save! if (@state != @js_rec.blob)
    end
  end
end