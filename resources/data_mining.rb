require 'json'

# ETL - Extract, Transform, Load

#
# Module rankings - From Metasploit, check out the wiki for what it means
#
ManualRanking = 0
LowRanking = 100
AverageRanking = 200
NormalRanking = 300
GoodRanking = 400
GreatRanking = 500
ExcellentRanking = 600
RankingName =
  {
    ManualRanking => "manual",
    LowRanking => "low",
    AverageRanking => "average",
    NormalRanking => "normal",
    GoodRanking => "good",
    GreatRanking => "great",
    ExcellentRanking => "excellent"
  }

# Step 1) Get our array of modules
json = File.read("info/module_metadata.json")
data = JSON.parse(json)
# data = data.reverse.take(50)
# data = data.select { |mod| mod['path'] =~ /grafana_auth_bypass/ }

# Step 2) Create a new intermediate data structure which:
#   - Filters out the no longer required modules
#   - Groups data into its corresponding sections

def session_required?(mod)
  mod['session_types'].kind_of?(Array) && mod['options'].any? { |options| options['name'] == "SESSION" && options['required'] == true }
end

def rhosts_option(mod)
  mod['options'].find do |option|
    option['name'].casecmp?('RHOSTS') && option['type'] == 'addressrange'
  end
end

def rport_option(mod)
  mod['options'].find do |option|
    # External modules use lowercase
    option['name'].casecmp?('RPORT') && (option['type'] == 'port' || option['type'] == 'integer')
  end
end

def target_uri_option(mod)
  mod['options'].find do |option|
    option['type'] == 'string' &&
      (option['name'] == 'TARGETURI' || option['name'] == 'TARGET_URI') &&
      option['required'] == true
  end
end

def required?(option)
  option['required'] == true
end

def default?(option)
  option['default'] != ''
end

# Extracted from lib/msf/core/module.rb
def required_cred_options(mod)
  mod['options'].select { |opt|
    (
    opt['type'] == 'string' &&
      required?(opt) &&
      (opt['name'].match(/user(name)*$/i) || opt['name'].match(/pass(word)*$/i))
    ) ||
      (
      opt['type'] == 'bool' &&
        required?(opt) &&
        opt['name'].match(/^allow_guest$/i)
      )
  }
end

transformed_data = data.map do |mod|
  has_targets = !mod['targets'].nil?
  has_default_credentials = mod['default_credential'] != false

  has_rhost_option = !rhosts_option(mod).nil?
  has_rport_option = !rport_option(mod).nil?
  has_target_uri_option = !target_uri_option(mod).nil?

  has_allowed_module_path = (
    !mod['path'].include?("/browser/") &&
      !mod['path'].include?("/fileformat/") &&
      !mod['path'].include?("/hwbridge/") &&
      !mod['path'].include?("/hams/") &&
      !mod['path'].include?("/ut2004_secure/") &&
      !mod['path'].include?("/android/")
  )
  has_all_options_defaultable = !mod['options'].any? do |option|
    next if option['name'].casecmp?('RHOSTS')

    required?(option) && !default?(option)
  end
  is_dos_module = (
    mod['mixins'].include?('Msf::Auxiliary::Dos') ||
      mod['mixins'].include?('Msf::Auxiliary::DRDoS') ||
      mod['path'].include?("/dos/") ||
      mod['path'].end_with?("/chromecast_reset.rb")
  )
  # TODO: Filter out external modules
  # TODO: Filter out scanners? Fuzzers? Brute forcers?
  # TODO: Some modules have arbitrary deletes, which doesn't seem safe
  # TODO: Some modules have 'targets' specified, i.e. it's not just enough to point a module at a server
  #       - modules/exploits/multi/http/jenkins_xstream_deserialize
  #       - modules/exploits/multi/http/struts_code_exec_parameters.rb
  is_fuzzer_or_scanner_or_bruteforcer = (
    mod['mixins'].include?('Msf::Auxiliary::AuthBrute') ||
      mod['mixins'].include?('Msf::Auxiliary::Scanner')
  )

  has_any_matches = [
    has_targets,
    has_default_credentials,
    has_rhost_option,
    has_rport_option && default?(rport_option(mod)),
  ].any?

  is_session_required = session_required?(mod)

  if is_session_required
    is_shown = has_any_matches && has_allowed_module_path && !is_dos_module
  else
    is_shown = has_any_matches && has_allowed_module_path && has_all_options_defaultable && !is_dos_module
  end

  if has_rhost_option
    grouping = 'remote'
  elsif is_session_required || !has_rhost_option
    grouping = 'local'
  end

  mod.merge(
    'has_targets' => has_targets,
    'has_default_credentials' => has_default_credentials,
    'has_rhost_option' => has_rhost_option,
    'has_rport_option' => has_rport_option,
    'has_target_uri_option' => has_target_uri_option,
    'has_allowed_module_path' => has_allowed_module_path,
    'has_all_options_defaultable' => has_all_options_defaultable,
    'is_dos_module' => is_dos_module,
    'is_fuzzer_or_scanner_or_bruteforcer' => is_fuzzer_or_scanner_or_bruteforcer,

    'is_shown' => is_shown,
    'grouping' => grouping
  )
end

# Step 3) Convert data into presentational concerns
#   Generate markdown
#   Generate json files
# puts JSON.pretty_generate(transformed_data)

def render_option_tick(option)
  if option.nil?
    '-'
  elsif default?(option)
    '✓'
  else
    '✗'
  end
end

def render_targets_tick(mod)
  if !mod['targets']
    '-'
  elsif mod['targets'] && (mod['targets'].length == 1 || mod['targets'].any? { |target| target =~ /Automatic/ })
    '✓'
  else
    '✗'
  end
end

def render_credential_tick(mod)
  if required_cred_options(mod).empty?
    '-'
  elsif mod['has_default_credentials']
    '✓'
  else
    '✗'
  end
end

def render_modules(modules)
  modules_grouped_by_ranking = modules.group_by { |mod| mod['rank'] }.sort
  modules_grouped_by_ranking.map do |(ranking, modules)|
    rank_heading = <<~EOF

      ### #{RankingName[ranking].capitalize} Ranking (#{modules.count})

    EOF
    modules_grouped_by_year = modules.group_by { |mod| (mod['disclosure_date'] || 'No Disclosure Date').split('-')[0] }.sort_by { |year, _mods| year }.to_h
    yearly_tables = modules_grouped_by_year.map do |year, modules|
      year_heading = <<~EOF
        #### #{year} (#{modules.count})

        | # | Module Name | Module Path | Targets | Credentials | RHOST | RPORT | URI |
        | :---: | :--- | :--- | :----: | :----: | :----: | :---: | :---: |
      EOF

      rows = modules.each_with_index.map do |mod, i|
        [
          i + 1,
          mod['name'],
          mod['fullname'],
          render_targets_tick(mod),
          render_credential_tick(mod),
          render_option_tick(rhosts_option(mod)),
          render_option_tick(rport_option(mod)),
          render_option_tick(target_uri_option(mod)),
        ].join('|')
      end.join("\n")

      year_heading + rows
    end.join("\n\n")

    rank_heading + yearly_tables
  end.join("\n\n")
end

def render_ranking_tally(modules)
  tally = modules.map { |mod| mod['rank'] }.tally.sort_by { |(rank, _count)| rank }
  tally.map do |(rank, count)|
    "\t- #{count} #{RankingName[rank].capitalize}"
  end.join("\n")
end

def create_markdown_file(modules)
  auxiliary = modules.select { |mod| mod['type'] == 'auxiliary' }
  exploits = modules.select { |mod| mod['type'] == 'exploit' }
  evasions = modules.select { |mod| mod['type'] == 'evasion' }

  <<~EOF
    # Module info

    ## Stats:
    - Total modules: #{(auxiliary + exploits + evasions).count}
    - Auxiliary #{auxiliary.count}
    #{render_ranking_tally(auxiliary)}
    - Exploits #{exploits.count}
    #{render_ranking_tally(exploits)}
    - Evasion #{evasions.count}
    #{render_ranking_tally(evasions)}

    ## Table legend
    - `✓` - Option present with default value provided
    - `✗` - Option present but no default value
    - `-` - Option not present

    ## Auxiliary (#{auxiliary.count})
    #{render_modules(auxiliary)}

    ## Exploits (#{exploits.count})
    #{render_modules(exploits)}

    ## Evasion (#{evasions.count})
    #{render_modules(evasions)}
  EOF
end

modules = transformed_data.select { |mod| mod['is_shown'] }
groupings = modules.group_by { |mod| mod['grouping'] }

groupings.each do |group_name, modules|
  File.write("info/module_list_#{group_name}.md", create_markdown_file(modules))
end

cve_ids = modules.flat_map { |mod| mod['references'] }.select { |ref| ref['type'] == 'CVE' }.map { |ref| "#{ref['type']}-#{ref['value']}" }.uniq.sort
File.write('info/cve_ids.json', JSON.pretty_generate(cve_ids))
