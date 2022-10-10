require 'account_controller'
require 'json'
require 'jwt'

class RedmineOauthController < AccountController
  include Helpers::MailHelper
  include Helpers::Checker
  def oauth_azure
    if Setting.plugin_redmine_omniauth_azure['azure_oauth_authentication']
      session['back_url'] = params['back_url']
      redirect_to oauth_client.auth_code.authorize_url(:redirect_uri => oauth_azure_callback_url, :scope => scopes)
    else
      password_authentication
    end
  end

  def oauth_azure_callback
    if params['error']
      flash['error'] = l(:notice_access_denied)
      redirect_to signin_path
    else
      token = nil
      begin
        token = oauth_client.auth_code.get_token(params['code'], :redirect_uri => oauth_azure_callback_url, :resource => "00000002-0000-0000-c000-000000000000")
      rescue OAuth2::Error => e
        flash[:error] = l(:notice_unable_to_obtain_azure_credentials) + " " + e.description
        redirect_to signin_path
        return
      end
      user_info = JWT.decode(token.token, nil, false)
      logger.error user_info

      email = user_info.first['unique_name']

      if Redmine::VERSION.to_s.starts_with?('2.')
        user = User.where(:mail => email).first
      else
        user = User.joins(:email_addresses).where(:email_addresses => { :address => email }).first
      end

      if user
        checked_try_to_login user.mail, user_info.first, user
      else
        if email
          user = User.new
          checked_try_to_login email, user_info.first, user
        else
          flash['error'] = l(:notice_no_verified_email_we_could_use)
          redirect_to signin_path
        end
      end
    end
  end

  def checked_try_to_login(email, info, user)
    if allowed_domain_for?(email)
      try_to_login email, info, user
    else
      flash[:error] = l(:notice_domain_not_allowed, :domain => parse_email(email)[:domain])
      redirect_to signin_path
    end
  end

  def try_to_login email, info, user
    params[:back_url] = session[:back_url]
    session.delete(:back_url)

    @user = user
    params = {}
    params["firstname"] = info["given_name"] unless info["given_name"].nil?
    params["lastname"] = info["family_name"] unless info["family_name"].nil?
    params["firstname"] ||= info["name"]
    params["lastname"] ||= info["name"]
    params["mail"] = email
    params["login"] = email
    logger.error login
    checkuser = User.find_by_login(login)
    logger.error checkuser
    if checkuser
      # Existing record
      if checkuser.active?
        checkuser.update_column(:last_login_on, Time.now)
        successful_authentication(checkuser)
      else
        account_pending(checkuser)
      end
    else
      if @user.new_record?
        # Self-registration off
        redirect_to(home_url) && return unless Setting.self_registration?
        # Create on the fly
        @user.login = login
        @user.safe_attributes = params
        @user.admin = false
        @user.random_password
        @user.register

        case Setting.self_registration
        when '1'
          register_by_email_activation(@user) do
            onthefly_creation_failed(@user)
          end
        when '3'
          register_automatically(@user) do
            onthefly_creation_failed(@user)
          end
        else
          register_manually_by_administrator(@user) do
            onthefly_creation_failed(@user)
          end
        end
      else
        # Existing record
        if @user.active?
          @user.update_column(:last_login_on, Time.now)
          successful_authentication(@user)
        else
          account_pending(@user)
        end
      end
    end
  end

  def oauth_client
    @client ||= OAuth2::Client.new(settings['client_id'], settings['client_secret'],
      :site => 'https://login.windows.net',
      :authorize_url => '/' + settings['tenant_id'] + '/oauth2/authorize',
      :token_url => '/' + settings['tenant_id'] + '/oauth2/token')
  end

  def settings
    @settings ||= Setting.plugin_redmine_omniauth_azure
  end

  def scopes
    'user:email'
  end
end