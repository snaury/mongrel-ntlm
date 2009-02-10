# Invaluable resources:
#  http://msdn2.microsoft.com/en-us/magazine/bb985043.aspx
#  http://doc.ddart.net/msdn/header/include/sspi.h.html

require 'mongrel'
require 'mongrel_ntlm/server_ntlm'

# Mongrel sends a Connection: Close to close off connections after each request
# but the NTLM handshake involves three legs on a persistent connection
module Mongrel
  module Const
    REMOTE_USER = 'REMOTE_USER'.freeze
    HTTP_VERSION = 'HTTP_VERSION'.freeze
    HTTP_CONNECTION = 'HTTP_CONNECTION'.freeze
    HTTP_AUTHORIZATION = 'HTTP_AUTHORIZATION'.freeze
    HTTP_X_MONGREL_PID = 'HTTP_X_MONGREL_PID'.freeze
    NTLM_STATUS_FORMAT = "HTTP/1.1 %d %s\r\nConnection: Keep-Alive\r\n".freeze
  end

  class NtlmRequestError < IOError
    # Dummy IOError to stop authentication
  end

  # Custom methods for supporting NTLM authentication requests
  module NtlmHttpRequest
    def ntlm_keepalive
      httpversion = (params[Const::HTTP_VERSION] || '').strip.upcase
      connection = (params[Const::HTTP_CONNECTION] || '').strip.downcase
      keepalive = httpversion == 'HTTP/1.0' ? false : true
      keepalive = false if connection == 'close'
      keepalive = true if connection == 'keep-alive'
      keepalive
    end

    def ntlm_token
      auth = params[Const::HTTP_AUTHORIZATION]
      return nil unless auth && auth.match(/\ANTLM (.*)\Z/)
      Base64.decode64($1.strip)
    end

    # Reinitialize HttpRequest object from the same socket
    # Mostly just the main loop of mongrel.
    def ntlm_refresh
      parser = HttpParser.new
      new_params = HttpParams.new
      new_data = @socket.readpartial(Const::CHUNK_SIZE)
      nparsed = 0

      @body.close
      while nparsed < new_data.length
        nparsed = parser.execute(new_params, new_data, nparsed)
        if parser.finished?
          new_params[Const::REQUEST_PATH] ||= @params[Const::REQUEST_PATH]
          raise "No REQUEST PATH" unless new_params[Const::REQUEST_PATH]
          raise "REQUEST URI mismatch" unless new_params[Const::REQUEST_URI] == @params[Const::REQUEST_URI]
          raise "REQUEST PATH mismatch" unless new_params[Const::REQUEST_PATH] == @params[Const::REQUEST_PATH]

          new_params[Const::PATH_INFO] = @params[Const::PATH_INFO]
          new_params[Const::SCRIPT_NAME] = @params[Const::SCRIPT_NAME]
          new_params[Const::REMOTE_ADDR] = @params[Const::REMOTE_ADDR]

          # We need to reinitialize with same @dispatchers, because browser might
          # start uploading data and we want to allow watching its progress
          initialize(new_params, @socket, @dispatchers)
          break
        else
          # Parser is not done, queue up more data to read and continue parsing
          chunk = @socket.readpartial(Const::CHUNK_SIZE)
          if !chunk or chunk.length == 0
            raise NtlmRequestError # read failed, stop processing
          end

          new_data << chunk
          if new_data.length >= Const::MAX_HEADER
            raise HttpParserError.new("HEADER is longer than allowed, aborting client early.")
          end
        end
      end
    rescue HttpParserError => e
      # We use new_params and new_data here, HttpServer#process_client won't display it for us :(
      STDERR.puts "#{Time.now}: HTTP parse error, malformed request (#{new_params[Const::HTTP_X_FORWARDED_FOR] || @socket.peeraddr.last}): #{e.inspect}"
      STDERR.puts "#{Time.now}: REQUEST DATA: #{new_data.inspect}\n---\nPARAMS: #{new_params.inspect}\n---\n"
      raise NtlmRequestError
    end
  end

  # Custom methods for supporting NTLM authentication responses
  module NtlmHttpResponse
    def send_ntlm_status(content_length=@body.length)
      unless @status_sent
        @header['Content-Length'] = content_length if content_length and @status != 304
        write(Const::NTLM_STATUS_FORMAT % [@status, @reason || HTTP_STATUS_CODES[@status]])
        @status_sent = true
      end
    end

    def ntlm_send
      send_ntlm_status
      send_header
    end

    def ntlm_reset
      initialize(@socket)
    end
  end
end

# Intercepts requests for the login page and injects the username in a request header
# if the user successfully completes NTLM authentication.
#
# Passes through to the regular login page if anything goes wrong.
class NtlmHandler < Mongrel::HttpHandler
  AUTHORIZATION_MESSAGE = <<END
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 NTLM Authorization Required</title>
</head><body>
<h1>NTLM Authorization Required</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
</body></html>
END

  def process(request, response)
    # clear headers of data that we did not set
    request.params.delete(Mongrel::Const::REMOTE_USER)
    request.params.delete(Mongrel::Const::HTTP_X_MONGREL_PID)

    # add NTLM capabilities to the request and response
    request.extend(Mongrel::NtlmHttpRequest)
    response.extend(Mongrel::NtlmHttpResponse)

    return request_auth(response, 'NTLM') if request.ntlm_token.nil?
    return request_auth(response) unless request.ntlm_keepalive # we need persistent connections

    ntlm = Win32::SSPI::ServerNtlm.new
    ntlm.acquire_credentials_handle

    process_type1_auth(ntlm, request, response)

    request.ntlm_refresh
    return request_auth(response) if request.ntlm_token.nil?

    process_type3_auth(ntlm, request, response)

    request.params[Mongrel::Const::REMOTE_USER] = ntlm.get_username_from_context
    request.params[Mongrel::Const::HTTP_X_MONGREL_PID] = Process.pid.to_s
  rescue IOError => e
    # There is not much we can do in case of IOError, besides
    # it usually means browser did something bad and we don't
    # have to care.
    # Make sure this request is not processed though
    response.done = true
  rescue
    STDERR.puts "#{Time.now}: NTLM authentication error: #{$!.inspect}"
    request_auth(response) # error or not, we do require authentication
  ensure
    ntlm.cleanup unless ntlm.nil?
  end

  protected

  # Sends authorization request back to browser
  def request_auth(response, auth = nil, finished = true)
    # make sure we don't produce IOError and don't stomp on another response
    return if response.done || response.socket.closed?
    response.start(401, finished) do |head,out|
      head['WWW-Authenticate'] = auth if auth
      head['Content-Type'] = 'text/html; charset=iso-8859-1'
      out.write(AUTHORIZATION_MESSAGE)
    end
  end

  # First leg of NTLM authentication is to process the Type 1 NTLM Message from the client.
  def process_type1_auth(ntlm, request, response)
    t1 = request.ntlm_token
    t2 = ntlm.accept_security_context(t1)
    request_auth(response, "NTLM #{t2}", false)
    response.ntlm_send
    response.ntlm_reset
  end

  # Third leg of NTLM authentication is to process the Type 3 NTLM Message from the client.
  def process_type3_auth(ntlm, request, response)
    t3 = request.ntlm_token
    t2 = ntlm.accept_security_context(t3)
    response.ntlm_reset
  end
end