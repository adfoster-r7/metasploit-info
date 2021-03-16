require 'json'

# ETL - Extract, Transform, Load

#
# Module rankings - From Metasploit, check out the wiki for what it means
#
ManualRanking       = 0
LowRanking          = 100
AverageRanking      = 200
NormalRanking       = 300
GoodRanking         = 400
GreatRanking        = 500
ExcellentRanking    = 600
RankingName         =
  {
    ManualRanking    => "manual",
    LowRanking       => "low",
    AverageRanking   => "average",
    NormalRanking    => "normal",
    GoodRanking      => "good",
    GreatRanking     => "great",
    ExcellentRanking => "excellent"
  }


json = File.read("info/module_metadata.json")
# Step 1) Get our array of modules
data = JSON.parse(json)
# data = data.reverse.take(50)
# data = data.select { |mod| mod['path'] =~ /gitstack_rest/ }

# Step 2) Create a new intermediate data structure which:
#   - Filters out the no longer required modules
#   - Groups data into its corresponding sections

def session_required?(mod)
  mod['session_types'].kind_of?(Array) && mod['options'].any? { |options| options['name'] == "SESSION" && options['required'] == true }
end

transformed_data = data.map do |mod|
  has_targets = !mod['targets'].nil?
  has_default_credentials = mod['default_credential'] != false
  has_rport_option = mod['options'].any? { |options| options['name'] == 'RPORT' && options['type'] == 'port' && options['required'] == true }
  has_target_uri_option = mod['options'].any? { |options| options['type'] == 'string' && options['name'] == 'TARGETURI' && options['required'] == true }
  has_allowed_module_path = (
    !mod['path'].include?("/browser/") &&
      !mod['path'].include?("/fileformat/") &&
      !mod['path'].include?("/hwbridge/") &&
      !mod['path'].include?("/hams/") &&
      !mod['path'].include?("/android/")
  )
  has_all_options_defaultable = !mod['options'].any? { |options| options['required'] == true && options['default'] == "" }

  has_any_matches = [
    has_targets,
    has_default_credentials,
    has_rport_option,
    has_target_uri_option,
  ].any?

  is_session_required = session_required?(mod)

  if is_session_required
    is_shown = has_any_matches && has_allowed_module_path
  else
    is_shown = has_any_matches && has_allowed_module_path && has_all_options_defaultable
  end

  mod.merge(
    'has_targets' => has_targets,
    'has_default_credentials' => has_default_credentials,
    'has_rport_option' => has_rport_option,
    'has_target_uri_option' => has_target_uri_option,
    'has_allowed_module_path' => has_allowed_module_path,
    'has_all_options_defaultable' => has_all_options_defaultable,

    'is_shown' => is_shown,
    'is_session_required' => is_session_required
  )
end

# Step 3) Convert data into presentational concerns
#   Generate markdown
#   Generate json files
# puts JSON.pretty_generate(transformed_data)

def render_modules(modules)
  modules_grouped_by_ranking = modules.group_by { |mod| mod['rank'] }.sort

  tables = modules_grouped_by_ranking.map do |(ranking, modules)|
    table_heading = <<~EOF
      ### #{RankingName[ranking].capitalize} Ranking (#{modules.count})

      | # | Module Name | Module Path | Target | Credentials | Port | URL |
      | :---: | :--- | :--- | :----: | :----: | :----: | :---: |
    EOF

    rows = modules.each_with_index.map do |mod, i|
      [
        i + 1,
        mod['name'],
        mod['fullname'],
        mod['has_targets'] ? 'Required' : '-',
        mod['has_default_credentials'] ? 'Required' : '-',
        mod['has_rport_option'] ? 'Required' : '-',
        mod['has_target_uri_option'] ? 'Required' : '-',
      ].join('|')
    end.join("\n")

    table_heading + rows
  end.join("\n\n")

  tables
end

def render_ranking_tally(modules)
  tally = modules.map { |mod| mod['rank'] }.tally.sort_by { |(rank, _count)| rank }
  tally.map do |(rank, count)|
    "\t- #{RankingName[rank].capitalize} - #{count}"
  end.join("\n")
end

def create_markdown_file(modules)
  auxiliary = modules.select { |mod| mod['type'] == 'auxiliary' }
  exploits = modules.select { |mod| mod['type'] == 'exploit' }
  evasions = modules.select { |mod| mod['type'] == 'evasion' }

  <<~EOF
    ## Module info
    
    ### Stats:
    - Total modules: #{(auxiliary + exploits + evasions).count}
    - Auxiliary #{auxiliary.count}
    #{render_ranking_tally(auxiliary)}
    - Exploits #{exploits.count}
    #{render_ranking_tally(exploits)}
    - Evasion #{evasions.count}
    #{render_ranking_tally(evasions)}

    ### Auxiliary (#{auxiliary.count})
    #{render_modules(auxiliary)}

    ### Exploits (#{exploits.count})
    #{render_modules(exploits)}

    ### Evasion (#{evasions.count})
    #{render_modules(evasions)}
  EOF
end

modules = transformed_data.select { |mod| mod['is_shown'] }
session_required = modules.select { |mod| mod['is_session_required'] }
session_not_required = modules.select { |mod| !mod['is_session_required'] }

cve_ids = modules.flat_map { |mod| mod['references'] }.select { |ref| ref['type'] == 'CVE' }.map { |ref| "#{ref['type']}-#{ref['value']}" }.uniq
File.write('info/new_module_list_session_required.md', create_markdown_file(session_required))
File.write('info/new_module_list_session_not_required.md', create_markdown_file(session_not_required))
File.write('info/new_cve_ids.json', JSON.pretty_generate(cve_ids))
