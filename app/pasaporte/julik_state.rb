# Camping session module is a wretched piece of junk, so we just replace it
require 'activerecord'
module JulikState
  class State < ActiveRecord::Base; set_table_name 'julik_states'; serialize :blob; end
  
  def self.create_schema
    return if State.table_exists?
    ActiveRecord::Schema.define do
      create_table :julik_states do | s |
        s.column :blob, :text
        s.column :sid, :string, :length => 32
        s.column :modified_at, :datetime
      end
      add_index :julik_states, [:sid], :unique => true
      State.reset_column_information
    end
  end
  
  RC = [*'A'..'Z'] + [*'0'..'9'] + [*'a'..'z']
  def _sid; (0...32).inject("") { |ret,_| ret << RC[rand(32)] }; end
  def _appn; self.class.to_s.split(/::/).shift; end
  def _ivar; @state ||= Camping::H[]; end
  
  
  eval("module Camping::Session; def service(*a); super(*a); end; end") if defined?(Camping::Session)
    
  def service(*a)
    fresh = Camping::H[_appn => Camping::H[]]
    s = State.find_by_sid(@cookies.jsid) || State.new(:sid => (@cookies.jlive_sid = _sid), :blob => fresh)
    @cookies.jsid, hash, check = s.sid, s.blob[_appn].dup, s.blob[_appn].hash
    _ivar.replace hash
    @msg = hash.delete(:msg)
    returning(super(*a)) {  s.update_attributes(:blob => s.blob.merge(_appn => _ivar)) unless check == _ivar.hash }
  end
end
