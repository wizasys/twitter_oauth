#!/usr/local/bin/ruby
# encoding: utf-8

require 'net/http'
require 'cgi'
require 'openssl'
require 'base64'


DIR_CONFIG_TWITTER_OAUTH = "#{ENV["HOME"]}/.config/twitter_oauth"
FILE_KEY = "#{DIR_CONFIG_TWITTER_OAUTH}/keys.txt"

uri_api = "https://api.twitter.com"
path1 = "/oauth/request_token"
path2 = "/oauth/authorize"

uri = URI(uri_api)

def get_keys
	file_key = File.open(FILE_KEY, 'r')
	lines = file_key.readlines
	consumer_key = lines[0].chomp
	$secret_key = lines[1].chomp
	file_key.close
	
	consumer_key
end

def sign(authorization_header, uri)
	authorization_header_keys = authorization_header.keys.sort

	signature_base_string_params = authorization_header_keys.map \
	 { |key| CGI.escape("#{key}=#{authorization_header[key]}") }.join(CGI.escape("&"))


	signature_base_string = "POST&#{CGI.escape(uri)}&" + signature_base_string_params

	signature = CGI.escape(
					Base64.strict_encode64(
							OpenSSL::HMAC.digest('sha1',
												 $secret_key + '&',
												 signature_base_string
												)
										  )
						  )
	signature
end

def make_authorization_header(authorization_header)
	authorization_header.map { |k,v| "#{k}=\"#{v}\"" }.join(", ")
end

consumer_key = get_keys

@http = Net::HTTP.new(uri.host, uri.port)
@http.use_ssl = true


characters = ('a'..'z').to_a + ('A'..'Z').to_a + (0 .. 9).to_a
nonce = (0..30).map{characters.sample}.join

authorization_header = {
	"oauth_consumer_key" => consumer_key,
	"oauth_signature_method" => "HMAC-SHA1",
	"oauth_timestamp" => Time.now.to_i.to_s,
	"oauth_nonce" => nonce,
	"oauth_version" => "1.0",
	"oauth_callback" => "oob"
}

signature = sign(authorization_header, uri_api + path1)

authorization_header["oauth_signature"] = signature

req = Net::HTTP::Post.new(path1)
req["Authorization"] = "OAuth " + make_authorization_header(authorization_header)

resp = @http.request(req)

split = CGI.parse(resp.body)

authorize_url = uri_api + path2
authorize_url += "?oauth_token=#{split["oauth_token"][0]}"

puts "Go to #{authorize_url}"
