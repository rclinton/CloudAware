#!/usr/bin/env ruby
#
# Description: The script for auto-discovery and registration of ELB, RDS, etc. in Zabbix
#

require 'rubygems'
require 'ostruct'
require 'optparse'
require 'parseconfig'
require 'logger'
require 'json'
require 'net/http'
require 'uri'
require 'zbxapi'
require 'aws-sdk'
require 'pp'
require 'ap'

default_options = OpenStruct.new(
  :api_url              => 'https://main-dot-cloudaware-vm.appspot.com/_ah/api/mainOps/v1/zabbix/customer',
  :customerid           => nil,
  :token                => nil,
  :getting_mode         => 'CA',
  :include_aws_accounts => [],
  :exclude_aws_accounts => [],
  :app_check            => [],
  :tags_elb             => ['Name'],
  :tags_rds             => ['Name'],
  :zbx_credentials      => "#{File.dirname(__FILE__)}/zbx_credentials",
  :conf_file            => "#{File.dirname(__FILE__)}/#{File.basename(__FILE__,'.rb')}.conf",
  :get_aws_account_list => false,
  :zabbix_template_elb  => 'Template_AWS_ELB',
  :zabbix_template_rds  => 'Template_AWS_RDS',
  :dry_run              => false,
  :log_file             => STDOUT,
  :log_level            => Logger::WARN,
  :mode => OpenStruct.new(
    :all => [
      'ELB',
      'RDS',
    ],
    :selected => [ nil ],
  ),
  :regions => OpenStruct.new(
    :public => [
      'us-east-1',
      'us-west-1',
      'us-west-2',
      'eu-west-1',
      'eu-central-1',
      'ap-southeast-1',
      'ap-southeast-2',
      'ap-northeast-1',
      'sa-east-1',
    ],
    :gov => [ 'us-gov-west-1' ],
    :selected => [ nil ],
  ),
)

# Log FATAL error message and exit with error code = 1
class Logger
  def fatal(progname = nil, &block)
    add(FATAL, nil, progname, &block)
    exit 1
  end
end

def parse_cmd_line_arguments(options)
  opts = OptionParser.new
  opts.summary_width = 35
  opts.banner = "Usage: #{__FILE__} OPTIONS"
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-I', '--customerid ID',                String, 'Customer ID.')                                             { |o| options.customerid = o }
  opts.on('-T', '--token TOKEN',                  String, 'Token.')                                                   { |o| options.token = o }
  opts.on('-m', '--mode "M1,M2"',                 Array,  'Working mode: ELB,RDS')                                    { |o| options.mode.selected = o.map { |i| i.strip } }
  opts.on('-g', '--getting-mode MODE',            String, 'Getting mode of resources: CA or AWS. Default: CA')        { |o| options.getting_mode = o }
  opts.on('-r', '--regions "R1,R2"',              Array,  'AWS regions.')                                             { |o| options.regions.selected = o.map { |i| i.strip } }
  opts.on('-z', '--zbx-credentials FILE',         String, 'Location of Zabbix credentials file.')                     { |o| options.zbx_credentials = o }
  opts.separator ''
  opts.separator 'Special options:'
  opts.on('-A', '--get-aws-accounts',             String, 'Getting AWS accounts of CA customer.')                     { options.get_aws_account_list = true }
  opts.on('-i', '--include-aws-accounts "A1,A2"', Array,  'Include specified AWS accouts.')                           { |o| options.include_aws_accounts = o.map { |i| i.strip } }
  opts.on('-e', '--exclude-aws-accounts "A1,A2"', Array,  'Exclude specified AWS accouts.')                           { |o| options.exclude_aws_accounts = o.map { |i| i.strip } }
  opts.on('-E', '--zabbix-template-elb "T1,T2"',  Array,  'ELB Zabbix template(s).')                                  { |o| options.zabbix_template_elb = o.map { |i| i.strip } }
  opts.on('-R', '--zabbix-template-rds "T1,T2"',  Array,  'RDS Zabbix template(s).')                                  { |o| options.zabbix_template_rds = o.map { |i| i.strip } }
  opts.on(      '--tags-elb "T1,T2"',             Array,  'Priority of ELB tags to create Zabbix visible name from.') { |o| options.tags_elb = o.map { |i| i.strip } }
  opts.on(      '--tags-rds "T1,T2"',             Array,  'Priority of RDS tags to create Zabbix visible name from.') { |o| options.tags_rds = o.map { |i| i.strip } }
  opts.separator ''
  opts.on('-c', '--conf-file FILE',               String, 'Config file.')                                             { |o| options.conf_file = o }
  opts.on('-l', '--log-file FILE',                String, 'Log file.')                                                { |o| options.log_file = o }
  opts.on('-v', '--verbose', 'Increase verbosity.')                                                                   { options.log_level = Logger::INFO }
  opts.on('-d', '--debug', 'Debug verbosity.')                                                                        { options.log_level = Logger::DEBUG }
  opts.on('-n', '--dry-run',                      String, 'Dry run - do not make any changes.')                       { options.dry_run = true }
  opts.on_tail('-h', '--help', 'Show this message.') do
    puts "#{opts}\n"
    exit
  end
  opts.parse!

  options
end

def check_required_options
  ['customerid', 'token'].each do |opt|
    error = $config ? ($config['Default'][opt].nil? ? true : false) : ($options.send(opt).nil? ? true : false)
    $options.log.fatal "Option '--#{ opt.gsub('_', '-') }' is required." if error
  end
end

def get_modes_list
  mode_selected = $config ? ($config['Default']['mode'] ? $config['Default']['mode'].split(',').map { |i| i.strip } : $options.mode.selected) : $options.mode.selected
  if mode_selected.last.nil?
    $options.mode.all
  elsif (mode_selected - $options.mode.all).empty?
    mode_selected
  else
    $options.log.fatal "Unknown mode '#{mode_selected.join(',')}'. It should be something like this: '#{$options.mode.all.join(',')}'"
  end
end

def get_regions_list(region_type)
  region_type.downcase!
  if ['public', 'gov'].include?(region_type)
    regions = $options.regions.send(region_type)
    regions_selected = $config ? ($config['Default']['regions'] ? $config['Default']['regions'].split(',').map { |i| i.strip } : $options.regions.selected) : $options.regions.selected
    if regions_selected.last.nil?
      regions
    elsif (regions_selected - regions).empty?
      regions_selected
    else
      $options.log.fatal "Unknown AWS regions '#{regions_selected.join(',')}'. It should be something like this: '#{regions.join(',')}'"
    end
  else
    $options.log.fatal "Unknown region type '#{region_type}'."
  end
end

def ca_api_request(
    api_url    = $config ? ($config['Default']['api_url']    ? $config['Default']['api_url']    : $options.api_url)    : $options.api_url,
    customerid = $config ? ($config['Default']['customerid'] ? $config['Default']['customerid'] : $options.customerid) : $options.customerid,
    token      = $config ? ($config['Default']['token']      ? $config['Default']['token']      : $options.token)      : $options.token,
    mode
  )
  case mode
  when 'AWS_ACCOUNTS'
    uri = URI.parse("#{api_url}/#{customerid}?token=#{token}")
  when 'ELB'
    uri = URI.parse("#{api_url}/#{customerid}/load-balancers?token=#{token}")
  when 'RDS'
    uri = URI.parse("#{api_url}/#{customerid}/db-instances?token=#{token}")
  else
    $options.log.fatal "Unnown mode '#{mode}'."
  end
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  begin
    response = http.get(uri.request_uri)
    raise response.message if response.code != '200'
    JSON.parse(response.body)
  rescue => e
    $options.log.fatal "Unable to get '#{mode}'. Error message: #{e.message}."
  end
end

def aws_services_hash(zbx_host_name, zbx_visible_name, zbx_description, zbx_hostgroup, zbx_template, aws_account_name, aws_account_id, aws_access_key, aws_secret_key, region, mode)
  {
    "zbx_host_name"    => zbx_host_name,
    "zbx_visible_name" => zbx_visible_name,
    "zbx_description"  => zbx_description,
    "zbx_hostgroup"    => zbx_hostgroup,
    "zbx_template"     => zbx_template,
    "aws_account_name" => aws_account_name,
    "aws_account_id"   => aws_account_id,
    "aws_access_key"   => aws_access_key,
    "aws_secret_key"   => aws_secret_key,
    "region"           => region,
    "mode"             => mode,
  }
end

def get_zbx_visible_name(mode, aws_account_name, service_tags, zbx_host_name)
  case mode
  when 'ELB'
    tags_selected = $config ? ($config.get_groups.include?(aws_account_name) ? ($config[aws_account_name].include?('tags-elb') ? $config[aws_account_name]['tags-elb'].split(',').map { |i| i.strip } : $options.tags_elb) : $options.tags_elb) : $options.tags_elb
  when 'RDS'
    tags_selected = $config ? ($config.get_groups.include?(aws_account_name) ? ($config[aws_account_name].include?('tags-rds') ? $config[aws_account_name]['tags-rds'].split(',').map { |i| i.strip } : $options.tags_rds) : $options.tags_rds) : $options.tags_rds
  else
    $options.log.fatal "Unnown mode '#{mode}'."
  end
  tags = []
  tags_selected.each do |tag_selected|
    case $options.getting_mode
    when 'CA'
      tags << service_tags.map { |tag| tag[1]       if tag[0]     == tag_selected }
    when 'AWS'
      tags << service_tags.map { |tag| tag['value'] if tag['key'] == tag_selected }
    end
  end
  tags.flatten!.compact!
  zbx_visible_name = tags.empty? ? "#{zbx_host_name} (#{aws_account_name})" : "#{tags.join(':')} (#{aws_account_name}) #{zbx_host_name}"
end

def get_aws_services_from_ca(mode, aws_accounts)
  aws_services = []
  zbx_template = $options.zabbix_template_elb if mode == 'ELB'
  zbx_template = $options.zabbix_template_rds if mode == 'RDS'
  aws_account_ids = aws_accounts.map { |aws_account| aws_account['_id'] }
  aws_services_from_ca = ca_api_request(mode)
  aws_services_from_ca['items'].each do |aws_service|
    aws_account_id   =  aws_service['ds__amazonAccount']
    deleted_from_aws = !aws_service['sf__disappearanceTime__c'].nil? ? true : false
    app_tier_name    = !aws_service['sf__applicationTierUniqueName__c'].nil? ? aws_service['sf__applicationTierUniqueName__c'] : false
    if aws_account_ids.include?(aws_account_id) and !deleted_from_aws
      aws_account      = aws_accounts.select { |aws_account| aws_account['_id'] == aws_account_id }.first
      aws_account_name = aws_account['name']
      aws_account_id   = aws_account['amazonAccountId']
      aws_access_key   = aws_account['accessKey']
      aws_secret_key   = aws_account['secretKey']
      zbx_host_name    = aws_service['sf__Name']
      service_tags     = JSON.parse(aws_service['sf__tagsJson__c']).to_a
      zbx_visible_name = get_zbx_visible_name(mode, aws_account_name, service_tags, zbx_host_name)
      zbx_description  = aws_service['sf__arn__c']
      zbx_hostgroup    = "#{aws_account_name}_#{mode}"
      region           = aws_service['sf__regionName__c']
      app_check        = $config ? ($config.get_groups.include?(aws_account_name) ? ($config[aws_account_name].include?('app_check') ? $config[aws_account_name]['app_check'].split(',').map { |i| i.strip } : $options.app_check) : $options.app_check) : $options.app_check
      $options.log.fatal "Unknown App check mode '#{app_check.join(',')}'. It should be something like this: '#{$options.mode.all.join(',')}'" unless (app_check - $options.mode.all).empty?
      if app_check.include?(mode)
        aws_services << aws_services_hash(zbx_host_name, zbx_visible_name, zbx_description, zbx_hostgroup, zbx_template, aws_account_name, aws_account_id, aws_access_key, aws_secret_key, region, mode) if app_tier_name
      else
        aws_services << aws_services_hash(zbx_host_name, zbx_visible_name, zbx_description, zbx_hostgroup, zbx_template, aws_account_name, aws_account_id, aws_access_key, aws_secret_key, region, mode)
      end
    end
  end
  aws_services
end

def get_aws_services_from_aws(aws_account_name, aws_account_id, aws_access_key, aws_secret_key, region, mode)
  aws_services = []
  Aws.config.update({ region: region, credentials: Aws::Credentials.new(aws_access_key, aws_secret_key) })
  case mode
  when 'ELB' ###########################################################################################################################################################################
    begin
      elasticloadbalancing = Aws::ElasticLoadBalancing::Client.new
      load_balancers = elasticloadbalancing.describe_load_balancers.load_balancer_descriptions
      load_balancers.each do |load_balancer|
        load_balancer_tags = elasticloadbalancing.describe_tags({ load_balancer_names: [load_balancer['load_balancer_name']] }).tag_descriptions
        load_balancer_tags.each do |load_balancer_tag|
          zbx_host_name    = load_balancer_tag['load_balancer_name']
          zbx_visible_name = get_zbx_visible_name(mode, aws_account_name, load_balancer_tag.tags, zbx_host_name)
          zbx_hostgroup    = "#{aws_account_name}_#{mode}"
          zbx_template     = $options.zabbix_template_elb
          aws_services << aws_services_hash(zbx_host_name, zbx_visible_name, zbx_hostgroup, zbx_template, aws_account_name, aws_account_id, aws_access_key, aws_secret_key, region, mode)
        end
      end
    rescue Aws::ElasticLoadBalancing::Errors::ServiceError => err
      $options.log.error "Unable to get #{mode} services. Error message: #{err}"
    end
  when 'RDS' ###########################################################################################################################################################################
    begin
      rds = Aws::RDS::Client.new
      db_instances = rds.describe_db_instances.db_instances
      db_instances.each do |db_instance|
        db_instance_tags = rds.list_tags_for_resource({ resource_name: "arn:aws:rds:#{region}:#{aws_account_id}:db:#{db_instance['db_instance_identifier']}" }).tag_list
        zbx_host_name    = db_instance['db_instance_identifier']
        zbx_visible_name = get_zbx_visible_name(mode, aws_account_name, db_instance_tags, zbx_host_name)
        zbx_hostgroup    = "#{aws_account_name}_#{mode}"
        zbx_template     = $options.zabbix_template_rds
        aws_services << aws_services_hash(zbx_host_name, zbx_visible_name, zbx_hostgroup, zbx_template, aws_account_name, aws_account_id, aws_access_key, aws_secret_key, region, mode)
      end
    rescue Aws::RDS::Errors::ServiceError => err
      $options.log.error "Unable to get #{mode} services. Error message: #{err}"
    end
  else #################################################################################################################################################################################
    $options.log.fatal "Unnown mode '#{mode}'."
  end
  $options.log.debug "#{aws_services.size} #{mode} found in '#{region}' region."
  aws_services
end

def tab_pad(label, tab_stop = 4)
  label_tabs = label.length / 8
  label.ljust(label.length + tab_stop - label_tabs, "\t")
end

$options = parse_cmd_line_arguments(default_options)
$options.log = Logger.new($options.log_file, 'monthly')
$options.log.level = $options.log_level
$config = File.exists?($options.conf_file) ? ParseConfig.new($options.conf_file) : false
check_required_options

####################################
# Read and check Zabbix credentials
if File.exists?($options.zbx_credentials)
  zbx_credentials = ParseConfig.new($options.zbx_credentials)
  zbx_user = zbx_credentials['user']
  zbx_pass = zbx_credentials['pass']
  zbx_url  = zbx_credentials['url']
  $options.log.fatal "Zabbix credentials not found in '#{$options.zbx_credentials}' file." if zbx_user.nil? || zbx_pass.nil? || zbx_url.nil?
else
  $options.log.fatal "Unable to open Zabbix credentials file '#{$options.zbx_credentials}'"
end

########################################################################################################################################################

aws_accounts_full = ca_api_request('AWS_ACCOUNTS')
aws_accounts = aws_accounts_full['amazonAccounts']

# Getting AWS accounts of CA customer.
if $options.get_aws_account_list
  puts "AWS accounts of CloudAware Customer: '#{aws_accounts_full['name']}'"
  if $options.log_level == Logger::DEBUG
    ap aws_accounts_full
  else
    puts "#{tab_pad('AccountName:')}#{tab_pad('AccountId:')}#{tab_pad('AccessKey:')}SecretKey:" if $options.log_level == Logger::INFO
    aws_accounts.each do |aws_account|
      if $options.log_level == Logger::INFO
        puts "#{tab_pad(aws_account['name'])}#{tab_pad(aws_account['amazonAccountId'])}#{tab_pad(aws_account['accessKey'])}#{aws_account['secretKey']}"
      else
        puts "#{aws_account['name']}"
      end
    end
  end
  exit
end

# Including or excluding specified AWS accounts of CA customer.
include_aws_accounts = $config ? ($config['Default']['include-aws-accounts'] ? $config['Default']['include-aws-accounts'].split(',').map { |i| i.strip } : $options.include_aws_accounts) : $options.include_aws_accounts
exclude_aws_accounts = $config ? ($config['Default']['exclude-aws-accounts'] ? $config['Default']['exclude-aws-accounts'].split(',').map { |i| i.strip } : $options.exclude_aws_accounts) : $options.exclude_aws_accounts
if include_aws_accounts or exclude_aws_accounts
  aws_account_names = aws_accounts.map { |aws_account| aws_account['name'] }
  aws_account_names_selected = include_aws_accounts.empty? ? exclude_aws_accounts : include_aws_accounts
  if (aws_account_names_selected - aws_account_names).empty?
    aws_accounts.select!   { |aws_account| aws_account_names_selected.include?(aws_account['name']) } unless include_aws_accounts.empty?
    aws_accounts.delete_if { |aws_account| aws_account_names_selected.include?(aws_account['name']) } unless exclude_aws_accounts.empty?
  else
    $options.log.fatal "Unknown AWS account(s) '#{aws_account_names_selected.join(',')}'. It should be something like this: '#{aws_account_names.join(',')}'"
  end
end

# Connect to Zabbix
zbx = ZabbixAPI.new(zbx_url, :verify_ssl => false, :http_timeout => 300 )
zbx.login(zbx_user,zbx_pass)
#pp zbx.api_info "host.create", :version=>"3.0"
#exit

# Checking Zabbix templates.
zabbix_templates = [ $options.zabbix_template_elb, $options.zabbix_template_rds ]
zbx_templates = zbx.template.get
zbx_templates.select! { |zbx_template| zabbix_templates.include?(zbx_template['name']) }
zabbix_templates_not_existent = zabbix_templates - zbx_templates.map { |zbx_template| zbx_template['name'] }
$options.log.fatal "Zabbix template(s) '#{zabbix_templates_not_existent.join(',')}' not found. Create them in Zabbix manually." unless zabbix_templates_not_existent.empty?

# Getting AWS services.
aws_services = []
get_modes_list.each do |mode|
  case $options.getting_mode
  when 'CA'
    aws_services << get_aws_services_from_ca(mode, aws_accounts)
  when 'AWS'
    aws_accounts.each do |aws_account|
      regions = get_regions_list(aws_account['regionType'])
      regions.each do |region|
        $options.log.debug "Mode: '#{mode}', AWS account: '#{aws_account['name']}', Region: '#{region}'."
        aws_services << get_aws_services_from_aws(aws_account['name'], aws_account['amazonAccountId'], aws_account['accessKey'], aws_account['secretKey'], region, mode)
      end
    end
  else
    $options.log.fatal "Unknown getting mode '#{$options.getting_mode}'. It must be CA (by default) or AWS."
  end
end
aws_services.flatten!
aws_services.compact!
aws_services_zbx_host_names = aws_services.map { |aws_service| aws_service['zbx_host_name'] }
#ap aws_services

# Getting new Zabbix hosts to add into
zbx_hosts_full = zbx.host.get({ 'output' => 'extend', 'selectGroups' => 'extend' })
zbx_hosts = zbx_hosts_full.map { |host| host['host'] }
new_zbx_hosts = aws_services.reject { |aws_service| zbx_hosts.include?(aws_service['zbx_host_name']) }
#ap zbx_hosts_full

# Getting old Zabbix hosts to be deleted from
old_zbx_hosts = zbx_hosts_full.reject { |zbx_host| aws_services_zbx_host_names.include?(zbx_host['host']) or zbx_host['groups'].first['name'] !~ /^.*_#{$options.mode.all.join('$|^.*_')}$/ }
old_zbx_host_hostids = old_zbx_hosts.map { |old_zbx_host| old_zbx_host['hostid'] }

# Getting Zabbix hosts that need to have 'Zabbix Visible name' or 'Description' updated.
update_zbx_hosts = []
zbx_hosts_full.each do |zbx_host|
  aws_services.each do |aws_service|
    if (aws_service['zbx_host_name'] == zbx_host['host'] and aws_service['zbx_visible_name'] != zbx_host['name']        and aws_service['zbx_visible_name'] != '') or \
       (aws_service['zbx_host_name'] == zbx_host['host'] and aws_service['zbx_description']  != zbx_host['description'] and aws_service['zbx_description']  != '')
      update_zbx_hosts << aws_service.merge({"zbx_hostid" => zbx_host['hostid']})
    end
  end
end

# Updating Zabbix hosts with new Zabbix Visible name.
unless update_zbx_hosts.empty?
  if $options.dry_run
    $options.log.warn "Dry run - #{update_zbx_hosts.size} Zabbix host(s) will be updated:"
  else
    $options.log.info "#{update_zbx_hosts.size} Zabbix host(s) will be updated:"
  end
  update_zbx_hosts.each do |update_zbx_host|
    if $options.dry_run
      $options.log.warn "Dry run - '#{update_zbx_host['mode']}' Zabbix Host: #{update_zbx_host['zbx_host_name']}\t New Visible name: #{update_zbx_host['zbx_visible_name']}"
    else
      begin
        zbx.host.update({
          'hostid'      => update_zbx_host['zbx_hostid'],
          'host'        => update_zbx_host['zbx_host_name'],
          'name'        => update_zbx_host['zbx_visible_name'],
          'description' => update_zbx_host['zbx_description']
        })
        $options.log.info "'#{update_zbx_host['mode']}' Zabbix Host '#{update_zbx_host['zbx_host_name']}' updated. New Visible name: '#{update_zbx_host['zbx_visible_name']}'"
      rescue Exception => err
        $options.log.error "Zabbix host.update error: #{err}"
      end
    end
  end
else
  $options.log.info "No Zabbix host(s) to update."
end

# Creating new Zabbix host(s).
unless new_zbx_hosts.empty?
  # Creating new Zabbix Host Group(s).
  new_zabbix_hostgroups = new_zbx_hosts.map { |new_zbx_host| new_zbx_host['zbx_hostgroup'] }.uniq
  zbx_hostgroups = zbx.hostgroup.get
  zbx_hostgroup_names = zbx_hostgroups.map { |zbx_hostgroup| zbx_hostgroup['name'] }
  new_zabbix_hostgroups.delete_if { |new_zabbix_hostgroup| zbx_hostgroup_names.include?(new_zabbix_hostgroup) }
  unless new_zabbix_hostgroups.nil?
    new_zabbix_hostgroups.each do |new_zabbix_hostgroup|
      if $options.dry_run
        $options.log.warn "Dry run - New Zabbix hostgroup '#{new_zabbix_hostgroup}' will be created."
      else
        begin
          zbx.hostgroup.create({'name' => new_zabbix_hostgroup})
          $options.log.info "New Zabbix hostgroup '#{new_zabbix_hostgroup}' has successfully been created."
        rescue => err
          $options.log.fatal "New Zabbix hostgroup '#{new_zabbix_hostgroup}' has not been created. Error: #{err}"
        end
      end
    end
  end
  zbx_hostgroups = zbx.hostgroup.get
  # Creating new Zabbix host(s).
  if $options.dry_run
    $options.log.warn "Dry run - #{new_zbx_hosts.size} new Zabbix host(s) will be created:"
  else
    $options.log.info "#{new_zbx_hosts.size} new Zabbix host(s) will be created:"
  end
  new_zbx_hosts.each do |new_zbx_host|
    if $options.dry_run
      $options.log.warn "Dry run - '#{new_zbx_host['mode']}' Zabbix Host: #{new_zbx_host['zbx_host_name']}\t Visible name: #{new_zbx_host['zbx_visible_name']}"
    else
      begin
        zbx_hostgroup_id = zbx_hostgroups.map { |zbx_hostgroup| zbx_hostgroup['groupid'] if zbx_hostgroup['name'] == new_zbx_host['zbx_hostgroup'] }.compact.join
        zbx_template_id = zbx_templates.map { |zbx_template| zbx_template['templateid'] if zbx_template['name'] == new_zbx_host['zbx_template'] }.compact.join
        zbx.host.create({
          'host'        => new_zbx_host['zbx_host_name'],
          'name'        => new_zbx_host['zbx_visible_name'],
          'description' => new_zbx_host['zbx_description'],
          'interfaces'  => [
            {
              'type'    => '1',
              'ip'      => '127.0.0.1',
              'dns'     => 'localhost',
              'useip'   => '1',
              'main'    => '1',
              'port'    => '10050'
            }
          ],
          'macros'      => [
            {
              'macro'   => '{$ACCESS_KEY}',
              'value'   => new_zbx_host['aws_access_key']
            },
            {
              'macro'   => '{$SECRET_KEY}',
              'value'   => new_zbx_host['aws_secret_key']
            },
            {
              'macro'   => '{$REGION}',
              'value'   => new_zbx_host['region']
            }
          ],
          'groups'      => [ { 'groupid'    => zbx_hostgroup_id } ],
          'templates'   => [ { 'templateid' => zbx_template_id } ],
          'status'      => '0'
        })
        $options.log.info "'#{new_zbx_host['mode']}' Zabbix Host '#{new_zbx_host['zbx_host_name']}' created. Visible name: '#{new_zbx_host['zbx_visible_name']}'"
      rescue Exception => err
        $options.log.error "Zabbix host.create error: #{err}"
      end
    end
  end
else
  $options.log.info "No Zabbix host(s) to create."
end

# Deleting old Zabbix host(s).
unless old_zbx_hosts.empty?
  if $options.dry_run
    $options.log.warn "Dry run - #{old_zbx_hosts.size}' old Zabbix host(s) will be deleted:"
    old_zbx_hosts.each do |old_zbx_host|
      $options.log.warn "Dry run - '#{old_zbx_host['groups'].first['name']}' Zabbix Host: #{old_zbx_host['host']}\t Visible name: #{old_zbx_host['name']}"
    end
  else
    begin
      $options.log.warn "#{old_zbx_hosts.size}' old Zabbix host(s) will be deleted:"
      zbx.host.delete(old_zbx_host_hostids)
      old_zbx_hosts.each do |old_zbx_host|
        $options.log.warn "'#{old_zbx_host['groups'].first['name']}' Zabbix Host #{old_zbx_host['host']} deleted.\t Visible name: #{old_zbx_host['name']}"
      end
    rescue Exception => err
      $options.log.error "Zabbix host.delete error: #{err}"
    end
  end
else
  $options.log.info "No Zabbix host(s) to delete."
end
