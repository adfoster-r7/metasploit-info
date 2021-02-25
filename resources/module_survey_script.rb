## Script to crawl through `module_metadata_base.json` and return all modules that only require target, port,lomvom
#  credentials, or URL paths

require 'json'

# File handling
json = File.read("info/module_metadata.json")
parsed = JSON.parse(json)

# Initialising counts
no_sess_req_count = 1
sess_req_count = 1
total_count = 0
@data = []

# Handles to generic search that is shared between both Local & Remote modules
def gather_results(mod, mod_count, file)
  write = false

  if !mod['targets'].nil? || mod['default_credential'] != false ||
      mod['options'].any? { |options| options['type'] == 'port' && options['required'] == true && options['name'] == 'RPORT'}  ||
      mod['options'].any? { |options| options['type'] == 'string' && options['name'] == 'TARGETURI' && options['required'] == true }
    if !mod['path'].include?("/browser/") && !mod['path'].include?("/fileformat/") && !mod['path'].include?("/hwbridge/") && !mod['path'].include?("/hams/")

      target = mod['targets'].nil? ? '-' : 'Required'
      credentials = mod['default_credential'] == false ? '-' : 'Required'

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

      File.write(file, "| #{mod_count} | #{mod['name']} | #{mod['fullname']} | #{target} | #{credentials} | #{port} | #{url} |\n", mode: "a")
      write = true

      mod['references'].each do |ref|
        if ref.include?("https://cvedetails.com/cve/")
          record = {
            "name" => mod['name'],
            "path" => mod['fullname'],
            "CVE reference" => mod['references'].select{ |ref| ref.include?("cvedetails.com")},
            "target" => target,
            "credentials" => credentials,
            "port" => port,
            "url" => url
          }
          @data << record
        end
      end
    end
  end
  File.open("info/module_cve_reference_list.json", "w") do |f|
    f.write(JSON.pretty_generate(@data))
  end
  write
end

# Handles header formatting
def table_header(title, file)
  File.open(file, mode: "a") do |f|
    f.write("\n### #{title}\n")
    f.write("\n| # | Module Name | Module Path | Target | Credentials | Port | URL |\n")
    f.write("| :---: | :--- | :--- | :----: | :----: | :----: | :---: |\n")
  end
end

# Counts total modules surveyed
def total_modules(parsed, count, file)
  count += parsed.length
  File.open(file, "a") do |f|
    f.write("\n## Total modules surveyed: #{count} \n")
  end
end

# Handles conditions for sessions being required or not
def mod_search_by_type(parsed, count, mod_type, session)
  if session
    file = "info/module_list_session_required.md"
  else
    file = "info/module_list_no_session_required.md"
  end

  table_header(mod_type.capitalize, file)
  parsed.each do |mod|
    if mod['type'] == mod_type
      if session && mod['session_types'].kind_of?(Array) && !mod['options'].any? { |options| options['name'] == "SESSION" && options['required'] == true }
        count += 1 if gather_results(mod, count, file)
      elsif !session && mod['session_types'].nil?
        unless mod['options'].any? { |options| options['required'] == true && options['default'] == "" }
          count += 1 if gather_results(mod, count, file)
        end
      end
    end
  end
end

# Handles code flow and some formatting for .md file
def session_required(parsed, sess_req_count, total_count)
  file = "info/module_list_session_required.md"

  # Document title formatting
  File.open(file, mode: "w") do |f|
    f.write("# A survey of module options to identify modules which only require target, port, credentials, or URL paths\n")
    f.write("\n## Session required\n")
  end

  # Formatting to add module totals
  total_modules(parsed, total_count, file)

  # Loop through and verify if the module requires a session. If it does not, it's a Remote module
  mod_search_by_type(parsed, sess_req_count, 'auxiliary', true)
  mod_search_by_type(parsed, sess_req_count, 'exploit', true)
  mod_search_by_type(parsed, sess_req_count, 'evasion', true)
end

# Handles code flow and some formatting for .md file
def no_session_required(parsed, no_sess_req_count, total_count)
  file = "info/module_list_no_session_required.md"

  # Document title formatting
  File.open(file, mode: "w") do |f|
    f.write("# A survey of module options to identify modules which only require target, port, credentials, or URL paths\n")
    f.write("\n## No session required\n")
  end

  # Formatting to add module totals
  total_modules(parsed, total_count, file)

  # Loop through and verify if the module requires a session. If it does not, it's a Remote module
  mod_search_by_type(parsed, no_sess_req_count, 'auxiliary', false)
  mod_search_by_type(parsed, no_sess_req_count, 'exploit', false)
  mod_search_by_type(parsed, no_sess_req_count, 'evasion', false)
end

session_required(parsed, sess_req_count, total_count)
no_session_required(parsed, no_sess_req_count, total_count)
