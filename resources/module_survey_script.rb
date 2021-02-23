## Script to crawl through `module_metadata_base.json` and return all modules that only require target, port,
#  credentials, or URL paths

require 'json'

# File handling
json = File.read("info/module_metadata.json")
parsed = JSON.parse(json)

# Initialising counts
no_sess_req_count = 1
sess_req_count = 1
total_count = 0

# Document title formatting
File.write("info/module_survey_results.md", "\n# A survey of module options to identify modules which only require target, port, credentials, or URL paths\n", mode: "a")

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

def table_header(title)
  File.write("info/module_survey_results.md", "\n### #{title}\n" \
             "\n| # | Module Name | Module Path | Target | Credentials | Port | URL |\n" \
             "| :---: | :--- | :--- | :----: | :----: | :----: | :---: |\n", mode: "a")
end

def total_modules(parsed, count)
  parsed.each do |mod|
    count += 1
  end
  File.write("info/module_survey_results.md", "\n## Total modules surveyed: #{count} \n", mode: "a")
end

def mod_search_by_type(parsed, count, mod_type, session)
  parsed.each do |mod|
    if mod['type'] == mod_type
      if session && mod['session_types'].kind_of?(Array)
        if gather_results(mod, count)
          count += 1
        end
      elsif !session && mod['session_types'].nil?
        if gather_results(mod, count)
          count += 1
        end
      end
    end
  end
end

def session_required(parsed, sess_req_count)
  # Table header and formatting for Remote Modules
  File.write("info/module_survey_results.md", "\n## Session required\n", mode: "a")
  # Table header will be added for each module type
  table_header("Auxiliary")
  # Loop through and verify if the module requires a session. If it does not, it's a Remote module
  mod_search_by_type(parsed, sess_req_count, 'auxiliary', true)
  table_header("Exploit")
  mod_search_by_type(parsed, sess_req_count, 'exploit', true)
  table_header("Evasion")
  mod_search_by_type(parsed, sess_req_count, 'evasion', true)
  table_header("Payload")
end

def no_session_required(parsed, no_sess_req_count)
  # Table header and formatting for Remote Modules
   File.write("info/module_survey_results.md", "\n## No Session required\n", mode: "a")
  # Table header will be added for each module type
  table_header("Auxiliary")
  # Loop through and verify if the module requires a session. If it does not, it's a Remote module
  mod_search_by_type(parsed, no_sess_req_count, 'auxiliary', false)
  table_header("Exploit")
  mod_search_by_type(parsed, no_sess_req_count, 'exploit', false)
  table_header("Evasion")
  mod_search_by_type(parsed, no_sess_req_count, 'evasion', false)
end

total_modules(parsed, total_count)
session_required(parsed, sess_req_count)
no_session_required(parsed, no_sess_req_count)
