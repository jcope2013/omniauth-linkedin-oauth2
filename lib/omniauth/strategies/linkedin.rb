require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class LinkedIn < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, 'linkedin'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :site => 'https://api.linkedin.com',
        :authorize_url => 'https://www.linkedin.com/oauth/v2/authorization?response_type=code',
        :token_url => 'https://www.linkedin.com/oauth/v2/accessToken'
      }

      option :scope, 'r_basicprofile r_emailaddress'
      option :fields, ['id', 'email-address', 'first-name', 'last-name', 'headline', 'location', 'industry', 'picture-url', 'public-profile-url']
      option :api_version, 'v1'

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid { raw_info['id'] }

      info do
        if options.api_version == "v1"
        {
          :name => user_name,
          :email => raw_info['emailAddress'],
          :nickname => user_name,
          :first_name => raw_info['firstName'],
          :last_name => raw_info['lastName'],
          :location => raw_info['location'],
          :description => raw_info['headline'],
          :image => raw_info['pictureUrl'],
          :urls => {
            'public_profile' => raw_info['publicProfileUrl']
          }
        }
        elsif options.api_version == "v2"
        {
          :name => user_name,
          :email => '',
          :nickname => user_name,
          :first_name => raw_info['localizedFirstName'],
          :last_name => raw_info['localizedLastName'],
          :location => "", # LIv2 TODO
          :description => "",
          :image => "",  # LIv2 TODO - this is going to be nasty to fetch.
          :urls => {
            'public_profile' => "" # LIv2 TODO
          }
        }
        else
          {}
        end
      end

      extra do
        { 'raw_info' => raw_info }
      end

      def callback_url
        full_host + script_name + callback_path
      end

      alias :oauth2_access_token :access_token

      def access_token
        ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
          :mode => :query,
          :param_name => 'oauth2_access_token',
          :expires_in => oauth2_access_token.expires_in,
          :expires_at => oauth2_access_token.expires_at
        })
      end

      def raw_info
        if options.api_version == "v1"
          @raw_info ||= access_token.get("/v1/people/~:(#{option_fields.join(',')})?format=json").parsed
        elsif options.api_version == "v2"
          # LIv2 TODO should use a projection to limit what we're pulling back but we'll need two
          # different option_fields?
          # @raw_info ||= access_token.get("/v2/me?projection=(#{option_fields.join(',')})").parsed
          @raw_info ||= access_token.get("/v2/me").parsed
        else
          raise ArgumentError.new("Unexpected value for api_version option: #{options.api_version}")
        end
      end

      private

      def option_fields
        fields = options.fields
        fields.map! { |f| f == "picture-url" ? "picture-url;secure=true" : f } if !!options[:secure_image_url]
        fields
      end

      def user_name
        # LIv2 Gross.
        name = case options.api_version
               when "v1" then "#{raw_info['firstName']} #{raw_info['lastName']}".strip
               when "v2" then "#{raw_info['localizedFirstName']} #{raw_info['localizedLastName']}".strip
               else ""
               end
        name.empty? ? nil : name
      end
    end
  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'
