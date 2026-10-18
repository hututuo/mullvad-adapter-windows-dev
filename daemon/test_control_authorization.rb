# frozen_string_literal: true
require_relative 'test_account'

class MullvadControlAuthorizationTest < Minitest::Test
  ROUTES = %w[/select /reconnect /cities /cities/select /speedtest /speedtest/start /repair /diagnose /cancel /protection /account/login].freeze
  def setup
    @dir = Dir.mktmpdir('mullvad-control-auth')
    @adapter = MullvadAdapter.new(state_dir: @dir)
    @adapter.send(:load_account_manager)
    @capability = @adapter.instance_variable_get(:@account_capability)
  end
  def teardown
    FileUtils.remove_entry(@dir)
  end
  def request(path, authorization: nil, origin: nil, method: 'POST')
    headers = "#{method} #{path} HTTP/1.1\r\nContent-Length: 2\r\n"
    headers += "Authorization: #{authorization}\r\n" if authorization
    headers += "Origin: #{origin}\r\n" if origin
    socket = MullvadAccountTest::Socket.new(headers + "\r\n{}")
    @adapter.send(:handle_http, socket)
    socket.response.split[1]
  end
  def test_every_mutation_rejects_missing_or_incorrect_capability
    ROUTES.each do |path|
      assert_equal '403', request(path), path
      assert_equal '403', request(path, authorization: 'Bearer wrong'), path
    end
  end
  def test_browser_origin_is_rejected_even_with_valid_capability
    ROUTES.each { |path| assert_equal '403', request(path, authorization: "Bearer #{@capability}", origin: 'https://untrusted.invalid'), path }
  end
  def test_authorized_request_reaches_handler_and_read_only_status_still_works
    @adapter.define_singleton_method(:accepted_async) { |sock, *_args| respond(sock, 202, { id: 'controlled' }) }
    assert_equal '202', request('/repair', authorization: "Bearer #{@capability}")
    assert_equal '202', request('/diagnose', authorization: "Bearer #{@capability}")
    assert_equal '200', request('/status', method: 'GET')
  end
  def test_unavailable_capability_fails_closed
    @adapter.instance_variable_set(:@account_capability, nil)
    assert_equal '403', request('/repair', authorization: 'Bearer ')
  end
end
