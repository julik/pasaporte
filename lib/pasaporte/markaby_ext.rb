%w( action_pack action_controller action_view ).each { |e| require e }
# We use some Rails magic to make forms easier
class Markaby::Builder
  include ::ActionView::Helpers::FormHelper
  include ::ActionView::Helpers::FormOptionsHelper
  include ::ActionView::Helpers::TextHelper
  include ::ActionView::Helpers::DateHelper
end