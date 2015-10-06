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

uri = URI(uri_api)

file_key = File.open(FILE_KEY, 'r')
lines = file_key.readlines
consumer_key = lines[0].chomp
secret_key = lines[1].chomp
file_key.close

@http = Net::HTTP.new(uri.host, uri.port)
@http.use_ssl = true

authorization_header_keys = [ "oauth_consumer_key", "oauth_signature_method",
"oauth_timestamp", "oauth_nonce", "oauth_version", "oauth_callback" ]

authorization_header_keys = authorization_header_keys.sort

characters = ('a'..'z').to_a + ('A'..'Z').to_a + (0 .. 9).to_a
nonce = (0..30).map{characters.sample}.join

authorization_header = {
	"oauth_consumer_key" => consumer_key,
	"oauth_signature_method" => "HMAC-SHA1",
	"oauth_timestamp" => Time.now.to_i.to_s,
	"oauth_nonce" => nonce,
	"oauth_version" => "1.0",
	"oauth_signature" => "",
	"oauth_callback" => "oob"
}


signature_base_string_params = authorization_header_keys.map \
 { |key| CGI.escape("#{key}=#{authorization_header[key]}") }.join(CGI.escape("&"))


signature_base_string = "POST&#{CGI.escape(uri_api+path1)}&" + signature_base_string_params

signature = CGI.escape(
				Base64.strict_encode64(
						OpenSSL::HMAC.digest('sha1',
											 secret_key + '&',
											 signature_base_string
											)
									  )
				      )

authorization_header["oauth_signature"] = signature

str_header = authorization_header.map { |k,v| "#{k}=\"#{v}\"" }.join(", ")

req = Net::HTTP::Post.new(path1)
req["Authorization"] = "OAuth " + str_header

resp = @http.request(req)
p resp.body
