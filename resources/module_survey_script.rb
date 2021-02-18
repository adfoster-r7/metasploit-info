## Script to crawl through `module_metadata_base.json` and return all modules that only require target, port,
#  credentials, or URL paths

require 'json'

# File handling
json = File.read("info/module_metadata.json")
parsed = JSON.parse(json)

# Initialising counts
no_sess_req_count = 1
sess_req_count = 1

# Method to handle to generic search that is shared between both Local & Remote modules
def gather_results(mod, mod_count)
  if !mod['targets'].nil? || mod['default_credential'] != false ||
      mod['options'].any? { |options| options['type'] == 'port' && options['required'] == true && options['name'] == 'RPORT'}  ||
      mod['options'].any? { |options| options['type'] == 'string' && options['name'] == 'TARGETURI' && options['required'] == true }

    target = '-'
    unless mod['targets'].nil?
      target = 'Required'
    end
    credentials = '-'
    unless mod['default_credential'] == false
      credentials = 'Required'
    end
    port = '-'
    mod['options'].each do |options|
      if options['type'] == 'port' && options['name'] == 'RPORT' && options['required'] == true
        port = 'Required'
      end
    end
    url = '-'
    mod['options'].each do |options|
      if options['type'] == 'string' && options['name'] == 'TARGETURI' && options['required'] == true
        url = 'Required'
      end
    end
    File.write("info/module_survey_results.md", "| #{mod_count} | #{mod['name']} | #{mod['fullname']} | #{target} | #{credentials} | #{port} | #{url} |\n", mode: "a")
  end
end

def session_required(parsed, sess_req_count)
  # Table header and formatting for Local Modules
  File.write("info/module_survey_results.md", "# A survey of module options to identify modules which only require target, port, credentials, or URL paths\n" \
             "## Session required \n" \
             "\n | # | Module Name | Module Path | Target | Credentials | Port | URL |\n" \
             "| :---: | :--- | :--- | :----: | :----: | :----: | :---: |\n")
  # Loop through and verify if the module requires a session. If it does, it's a local module
  parsed.each do |mod|
    unless mod['type'] == 'payload' || mod['type'] == 'encoder' || mod['type'] == 'nop' || mod['options'].any? { |options| options['evasion'] == true }
      if mod['options'].any? { |options| options['type'] == 'bool' && options['name'] == 'CreateSession' }
        if gather_results(mod, sess_req_count)
          sess_req_count += 1
        end
      end
    end
  end
end

def no_session_required(parsed, no_sess_req_count)
  # Table header and formatting for Remote Modules
  File.write("info/module_survey_results.md", "\n\n## No session required\n" \
             "\n| # | Module Name | Module Path | Target | Credentials | Port | URL |\n" \
             "| :---: | :--- | :--- | :----: | :----: | :----: | :---: |\n", mode: "a")
  # Loop through and verify if the module requires a session. If it does not, it's a Remote module
  parsed.each do |mod|
    unless mod['type'] == 'payload' || mod['type'] == 'encoder' || mod['type'] == 'nop' || mod['options'].any? { |options| options['evasion'] == true }
      unless mod['options'].any? { |options| options['type'] == 'bool' && options['name'] == 'CreateSession' }
        if gather_results(mod, no_sess_req_count)
          no_sess_req_count += 1
        end
      end
    end
  end
end

session_required(parsed, sess_req_count)
no_session_required(parsed, no_sess_req_count)
