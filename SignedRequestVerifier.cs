using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FBSignedRequestValidator
{
	class SignedRequestVerifier
	{
		//Returns true if the signed request is valid for the given app secret.
		public static bool ValidateSignedRequest (string signedRequest, string appSecret)
		{
			string[] signedRequestTokens = signedRequest.Split ('.');
			
			if (signedRequestTokens.Length != 2)
      {
				return false;
			}

			string encodedHmacShaSignature = signedRequestTokens [0];
			string base64Json = signedRequestTokens [1];

			string signature = Base64UrlDecode (encodedHmacShaSignature);

			Dictionary<string, string> decodedPayload = DecodePayload (base64Json);

			string decodedAlgorithm = decodedPayload ["algorithm"];
			if (!decodedAlgorithm.Equals ("HMAC-SHA256", StringComparison.OrdinalIgnoreCase))
      {
				return false;
			}

			using (var cryto = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(appSecret))) {
				var hash = Convert.ToBase64String (cryto.ComputeHash (Encoding.UTF8.GetBytes (base64Json)));
				var decodedHash = Base64UrlDecode (hash);
				if (decodedHash != signature) 
        {
					return false;
				}
			}

			return true;
		}

		//Decodes the JSON payload and converts into a dictionary
		private static Dictionary<string, string> DecodePayload (string payload)
		{
			var encoding = new UTF8Encoding ();
			var decodedJson = payload.Replace ("=", string.Empty).Replace ('-', '+').Replace ('_', '/');
			var base64JsonArray = Convert.FromBase64String (decodedJson.PadRight (decodedJson.Length + (4 - decodedJson.Length % 4) % 4, '='));
			var json = encoding.GetString (base64JsonArray);
			var jObject = JObject.Parse (json);

			Dictionary<string, string> decodedPayload = new Dictionary<string, string> ();
			foreach (JProperty jp in jObject.Properties()) {
				decodedPayload [jp.Name] = jp.Value.ToString ();
			}
			return decodedPayload;
		}
		
		//Convert a string to bytes
		private static byte[] GetBytes (string str)
		{
			byte[] bytes = new byte[str.Length * sizeof(char)];
			Buffer.BlockCopy (str.ToCharArray (), 0, bytes, 0, bytes.Length);
			return bytes;
		}

		//Converts byte array to string
		private static string GetString (byte[] bytes)
		{
			char[] chars = new char[bytes.Length / sizeof(char)];
			Buffer.BlockCopy (bytes, 0, chars, 0, bytes.Length);
			return new string (chars);
		}

		//This is a direct translation of facebook's base64_url_decode from http://developers.facebook.com/docs/authentication/signed_request/
		private static string Base64UrlDecode (string encodedValue)
		{
			encodedValue = encodedValue.Replace ('+', '-').Replace ('/', '_').Trim ();
			int padding = encodedValue.Length % 4;
			if (padding > 0) {
				padding = 4 - padding;
			}

			encodedValue = encodedValue.PadRight (encodedValue.Length + padding, '=');
			return encodedValue;
		}
	}
}
