require File.dirname(__FILE__) + '/helper'

class TokenBoxTest < Test::Unit::TestCase
  def test_init
    assert_nothing_raised { TokenBox.new }
  end
  
  def test_procurement
    box = TokenBox.new
    tok = box.procure!("abc")
    assert_kind_of String, tok
    assert_equal TokenBox::TOKEN_SIZE, tok.length
    tokens = (0...30).map { box.procure!("abc") }.uniq
    assert_equal 30, tokens.uniq.length, "All generated tokens should differ"
    tokens.each do | tok |
      assert_equal TokenBox::TOKEN_SIZE, tok.length
    end
  end
  
  def test_validation_should_happen_once
    box = TokenBox.new
    tok = box.procure!("a")
    assert_nothing_raised { box.validate!("a", tok) }
    assert_raise(TokenBox::Invalid) { box.validate!("a", tok) }
  end

  def test_validation_should_work_for_the_request_only
    box = TokenBox.new
    tok = box.procure!("a")
    assert_raise(TokenBox::Invalid) { box.validate!("b", tok) }
    assert_nothing_raised { box.validate!("a", tok) }
  end
  
  def test_tokens_should_be_discarded
    box = TokenBox.new
    first = box.procure!("a")
    TokenBox::MAX_TOKENS.times  do
      box.procure!("a")
    end
    assert_raise(TokenBox::Invalid) { box.validate!("a", first)}
  end
  
  def test_token_should_expire
    box = TokenBox.new
    begin
      old, $VERBOSE, w = TokenBox::WINDOW, nil, $VERBOSE
      TokenBox.const_set(:WINDOW, 2)
      tok = box.procure!("a")
      sleep(2.3)
      assert_raise(TokenBox::Invalid) { box.validate!("a", tok)}
    ensure
      TokenBox.const_set(:WINDOW, old)
      $VERBOSE = w
    end
  end
end