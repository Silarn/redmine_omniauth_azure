require 'redmine'

Redmine::Plugin.register :redmine_omniauth_azure do
  name 'Redmine Omniauth Azure plugin'
  author 'Gucin Tsui'
  description 'This is a plugin for Redmine registration through Azure AD'
  version '0.0.1'
  url 'https://github.com/ares/redmine_omniauth_azure'
  author_url 'https://github.com/'

  settings :default => {
    :client_id => "",
    :client_secret => "",
    :github_oauth_autentication => false,
    :allowed_domains => ""
  }, :partial => 'settings/azure_settings'
end

if Rails.configuration.respond_to?(:autoloader) && Rails.configuration.autoloader == :zeitwerk
  Rails.autoloaders.each { |loader| loader.ignore(File.dirname(__FILE__) + '/lib') }
end
require File.dirname(__FILE__) + '/lib/redmine_omniauth_azure'