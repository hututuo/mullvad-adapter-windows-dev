# frozen_string_literal: true

# Minitest 6 plugins must not replace this runner and silently report zero tests.
gem 'minitest', '= 5.27.0'
ENV['MT_NO_PLUGINS'] = '1'
require 'minitest/autorun'
