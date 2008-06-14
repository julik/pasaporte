# Camping session module is a wretched piece of junk, so we just replace it
module JulikState
  require 'activerecord'
  class State < ActiveRecord::Base; set_table_name 'julik_states'; serialize :blob; end
  
  def self.create_schema
    return if State.table_exists?
    ActiveRecord::Schema.define do
      create_table :julik_states do | s |
        s.column :blob, :text
        s.column :sid, :string, :length => 32
        s.column :modified_at, :datetime
        s.column :created_at, :datetime
        s.column :app, :string, :null => false
      end
      add_index :julik_states, [:sid, :app], :unique => true
      State.reset_column_information
    end
  end
  RC = [*'A'..'Z'] + [*'0'..'9'] + [*'a'..'z']
  def _sid; (0...32).inject("") { |ret,_| ret << RC[rand(RC.length)] }; end
  def _appn; self.class.to_s.split(/::/).shift; end
  def _ivar; @state ||= Camping::H[]; end
  def _gc
  end
  
  def service(*a)
    fresh = Camping::H[{}]
    s = State.find_by_sid_and_app(@cookies.jsid, _appn) || State.new(:app => _appn, :blob => fresh,
      :sid => (@cookies.jlive_sid = _sid))
    _ivar.replace s.blob
    @msg = _ivar.delete(:msg)
    returning(super(*a)) {  s.update_attributes(:blob => _ivar) unless s.blob == _ivar }
  end
end