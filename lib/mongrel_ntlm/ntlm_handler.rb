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
    HTTP_AUTHORIZATION = 'HTTP_AUTHORIZATION'.freeze
    HTTP_X_MONGREL_PID = 'HTTP_X_MONGREL_PID'.freeze
    NTLM_STATUS_FORMAT = "HTTP/1.1 %d %s\r\n".freeze
  end

  # Custom methods for supporting NTLM authentication requests
  module NtlmHttpRequest
    def ntlm_token
      auth = params[Const::HTTP_AUTHORIZATION]
      return nil unless auth && auth.match(/\ANTLM (.*)\Z/)
      Base64.decode64($1.strip)
    end

    # Create a new HttpRequest object from the same socket and steal its body.
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
          break if !chunk or chunk.length == 0  # read failed, stop processing

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
      raise # request will be cancelled in ntlm handler
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
      @header.out.truncate(0)
      @body.close
      @body = StringIO.new
      @status_sent = @header_sent = @body_sent = false
    end
  end
end

# Intercepts requests for the login page and injects the username in a request header
# if the user successfully completes NTLM authentication.
#
# Passes through to the regular login page if anything goes wrong.
class NtlmHandler < Mongrel::HttpHandler
  def process(request, response)
    # clear headers of data that we did not set
    request.params.delete(Mongrel::Const::REMOTE_USER)
    request.params.delete(Mongrel::Const::HTTP_X_MONGREL_PID)

    # add NTLM capabilities to the request and response
    request.extend(Mongrel::NtlmHttpRequest)
    response.extend(Mongrel::NtlmHttpResponse)

    return request_auth(response) if request.ntlm_token.nil?

    ntlm = Win32::SSPI::ServerNtlm.new
    ntlm.acquire_credentials_handle

    process_type1_auth(ntlm, request, response)
    request.ntlm_refresh
    process_type3_auth(ntlm, request, response)

    request.params[Mongrel::Const::REMOTE_USER] = ntlm.get_username_from_context
    request.params[Mongrel::Const::HTTP_X_MONGREL_PID] = Process.pid.to_s
  rescue HttpParserError => e
    # The correct error was already displayed
    # Make sure it's not processed any further
    response.done = true
  rescue
    STDERR.puts "#{Time.now}: NTLM authentication error: #{$!.inspect}"
    # Don't leak response to any other handler
    response.done = true
  ensure
    ntlm.cleanup unless ntlm.nil?
  end

  protected

  # Sends authorization request back to browser
  def request_auth(response, auth = 'NTLM', finished = true)
    response.start(401, finished) do |gead,out|
      head['WWW-Authenticate'] = auth
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