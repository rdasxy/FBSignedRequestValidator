using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace FBSignedRequestValidator
{
  class Program
  {
    static void Main(string[] args)
    {
      string signedRequest = "quGaXrTLt6qdunxD4xX8BmEhu0bE2aZ1s_C4SweW26k.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImNvZGUiOiJBUUMxcUdUYU5OOTNsN01yM05KZEdVM3hzVXVUbXpZTjRDUUhKSzlBTzJtcnBfNkVZV0Z5WUkzRkxmYkxDX0x4R3d5UlliY1JXNTZ6XzRJcTZaWFZSQmFCOG5SamJ3S3djS2JxQ1BSNmswbEZvQ3J1VEh4X3g4eHRzaWk1MlRJVndBOTFiMHpSWEZxeks3bVd2cjBQeU4talg4Z25LRUtVWm80ZXhnZEVHRmZTemNFMUhVRVFocDk5eS0tcGY4OFdMOVkiLCJpc3N1ZWRfYXQiOjEzMzczODA3ODgsInVzZXJfaWQiOiI1ODUwMzIwODEifQ";
      string appSecret = "25aa16783d423d671e096e5d2ea66a9d";

      bool result = SignedRequestVerifier.ValidateSignedRequest(signedRequest, appSecret);

      Console.WriteLine("Valid? = " + result);
    }
  }
}
