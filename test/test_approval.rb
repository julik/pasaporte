require 'helper'

class TestApproval < Camping::ModelTest
  TATIVILLE_WIKI = 'http://tativille.fr/wiki/'
  fixtures :pasaporte_profiles
  
  def setup
    super; @hulot = Profile.find(1)
  end
  
  def test_associations_defined
    assert_kind_of Enumerable, @hulot.approvals, "An association for approvals should exist"
    assert_kind_of NilClass, Approval.new.profile
  end
  
  def test_presence_validations
    approval = Approval.new
    deny approval.valid?
    approval.profile = @hulot
    
    deny approval.valid?
    approval.trust_root = TATIVILLE_WIKI
    assert approval.valid?, "Now the approval is valid"
  end

  def test_uniqueness_validations
    approval = Approval.create :profile => @hulot, :trust_root => TATIVILLE_WIKI
    deny approval.new_record?
    assert_raise(ActiveRecord::RecordInvalid) do
      Approval.create! :profile => @hulot, :trust_root => TATIVILLE_WIKI
    end
  end
end