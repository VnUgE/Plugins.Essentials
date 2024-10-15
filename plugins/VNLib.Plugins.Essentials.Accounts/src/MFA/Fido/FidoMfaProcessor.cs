/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoMfaProcessor.cs 
*
* FidoMfaProcessor.cs is part of VNLib.Plugins.Essentials.Accounts which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

using FluentValidation;

using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading.Users;

using VNLib.Plugins.Essentials.Accounts.MFA.Fido.JsonTypes;

namespace VNLib.Plugins.Essentials.Accounts.MFA.Fido
{

    [ConfigurationName("fido_settings")]
    internal sealed class FidoMfaProcessor(PluginBase plugin, IConfigScope config) : IMfaProcessor
    {
        private static readonly FidoAuthValidator _authValidator = new();
        private static readonly FidoMessageValidator FidoReqVal = new();
        private static readonly FidoResponseValidator ResponseValidator = new();
        private static readonly FidoClientDataJsonValidtor ClientDataValidator = new();

        private static readonly FidoPubkeyAlgorithm[] _supportedAlgs =
        [
            new FidoPubkeyAlgorithm(algId: -7),    //ES256
            new FidoPubkeyAlgorithm(algId: -35),   //ES384     
            new FidoPubkeyAlgorithm(algId: -36),   //ES512
        ];

        private readonly FidoConfig _config = config.DeserialzeAndValidate<FidoConfig>();
        private readonly IUserManager _users = plugin.GetOrCreateSingleton<UserManager>();
        //private readonly ILogProvider _log = plugin.Log.CreateScope("FIDO");

        const string JwtClaimKey = "fido";

        ///<inheritdoc/>
        public string Type => "fido";

        ///<inheritdoc/>
        public void ExtendUpgradePayload(in JwtPayload message, IUser user)
        {
            FidoDeviceCredential[]? devices = user.FidoGetAllCredentials();

            /*
             * If no devices are stored on the user's profile then no 
             * authentication data to provide. If devices are stored,
             * extend the auth data to include a fido challenge.
             */
            if (devices == null || devices.Length == 0)
            {
                return;
            }

            using UnsafeMemoryHandle<byte> challBuffer = MemoryUtil.UnsafeAlloc(_config.ChallangeSize, true);

            RandomHash.GetRandomBytes(challBuffer.Span);

            message.AddClaim(
                claim: JwtClaimKey,
                value: GetChallengeData(_config, challBuffer.Span, devices)
            );
        }

        ///<inheritdoc/>
        public bool MethodEnabledForUser(IUser user) => user.FidoEnabled();

        ///<inheritdoc/>
        public bool ArmedForUser(IUser user) => user.FidoEnabled();

        ///<inheritdoc/>
        public bool VerifyResponse(IUser user, JsonElement request)
        {
            if(request.TryGetProperty("fido", out JsonElement fidoEl) == false)
            {
                return false;
            }

            //Get the json response and ensure a response object was supplied
            FidoUpgradeResponse? fidoResponse = fidoEl.Deserialize<FidoUpgradeResponse>();
            if (fidoResponse?.Response is null)
            {
                return false;
            }

            /*
             * This is an internal validation. It ensures the device 
             * response is valid and contains the necessary data to
             * complete the verification steps. It's not important 
             * that the user gets this feedback as it means their device
             * is sending bad data or it's not supported
             */
            if (!_authValidator.Validate(fidoResponse).IsValid)
            {
                return false;
            }

            FidoDeviceCredential? device = GetSelectedDevice(user, fidoResponse);

            if (device is null)
            {
                return false;
            }

            //Recover the client data from the response
            FidoClientDataJson clientData = Base64Util.DeserializeJson<FidoClientDataJson>(
                fidoResponse.Response.Base64UrlClientData
            )!;

            /*
             * The client challenge and site origin will be verified against the 
             * authenticated data returned by the signing device
             */
            if (!CheckChallengeMatches(_config, request, clientData))
            {
                return false;
            }

            //Verify the device's signature over it's signed data
            return VerifySignedData(fidoResponse.Response, device);
        }

        ///<inheritdoc/>
        public ValueTask<object?> OnUserGetAsync(HttpEntity entity, IUser user)
        {
            return ValueTask.FromResult<object?>(new UserGetResult
                {
                    Devices         = user.FidoGetAllCredentials() ?? [],
                    CanAddDevices   = user.FidoCanAddKey(),
                    DataSize        = user.FidoGetDataSize(),
                    MaxSize         = UserFidoMfaExtensions.MaxEncodedSize
                }
            );
        }

        ///<inheritdoc/>
        public async ValueTask<object?> OnHandleMessageAsync(HttpEntity entity, JsonElement request, IUser user)
        {
            ValErrWebMessage webm = new();

            using FidoRequestMessage? req = request.Deserialize<FidoRequestMessage>();
            if (webm.Assert(req != null, "Empty request message"))
            {
                return webm;
            }

            if (!FidoReqVal.Validate(req, webm))
            {
                return webm;
            }

            //If the request is password protected, verify the password
            if (IsPasswordProtected(req))
            {
                bool passwordValid = await VerifyPasswordAsync(user, req, webm, entity.EventCancellation);

                if (!passwordValid)
                {
                    return webm;
                }
            }

            switch (req.Action)
            {
                case "prepare_device":
                    
                    PrepareDevice(_config, entity, user, webm);
                    break;

                case "disable_all":
                    user.FidoDisable();

                    //Push changes to the database
                    await user.ReleaseAsync(entity.EventCancellation);

                    webm.Result = "Successfully disabled your TOTP authenticator";
                    webm.Success = true;
                    break;

                case "register_device":

                    if (webm.Assert(req.Registration != null, "Empty request message"))
                    {
                        break;
                    }

                    RegisterFidoDevice(user, webm, req.Registration);

                    //Push changes to database
                    await user.ReleaseAsync(entity.EventCancellation);

                    break;

                case "disable_device":

                    DeleteSingleDeviceAsync(user, webm, req.DeviceId);

                    //Push changes to database
                    await user.ReleaseAsync(entity.EventCancellation);

                    break;
            }

            return webm;
        }

        private static bool IsPasswordProtected(FidoRequestMessage req)
        {
            return req.Action switch
            {
                //Preparing the device does not alter the security state for the user
                "prepare_device" => false,

                //Default to pw required
                _ => true
            };
        }

        private async Task<bool> VerifyPasswordAsync(IUser user, FidoRequestMessage req, WebMessage webm, CancellationToken cancellation)
        {
            const string CheckPassword = "Please check your password";

            if (webm.Assert(!string.IsNullOrEmpty(req.Password), CheckPassword))
            {
                return false;
            }

            //Verify password against the user
            ERRNO result = await _users.ValidatePasswordAsync(
                user,
                req.Password,
                PassValidateFlags.None,
                cancellation
            );

            return !webm.Assert(result > 0, CheckPassword);
        }

        private static void PrepareDevice(FidoConfig config, HttpEntity entity, IUser user, ValErrWebMessage webm)
        {
            if (webm.Assert(user.FidoCanAddKey(), "You cannot add another key to this account. You must delete an existing one first"))
            {
                return;
            }

            //Get existing devices so they can be exlcuded from the registration process
            FidoExcludedDeviceDescriptor[]? excludedDevices = user.FidoGetAllCredentials()
                ?.Select(static d => new FidoExcludedDeviceDescriptor { DeviceId = d.Base64DeviceId! })
                .ToArray();

            //TODO: Store challenge in user session
            string challenge = RandomHash.GetRandomBase64(16);

            webm.Success = true;
            webm.Result = new FidoRegistrationMessage
            {
                AttestationType     = config.AttestationType,
                AuthSelection       = config.FIDOAuthSelection,
                RelyingParty        = new FidoRelyingParty
                {
                    Id              = entity.Server.RequestUri.DnsSafeHost,
                    Name            = config.SiteName
                },
                User = new FidoUserData
                {
                    UserId          = user.UserID,
                    UserName        = user.EmailAddress,
                    DisplayName     = user.EmailAddress,
                },
                Timeout             = config.Timeout,
                PubKeyCredParams    = _supportedAlgs,
                Base64Challenge     = challenge,
                ExcludedDevices     = excludedDevices
            };
        }

        private static void RegisterFidoDevice(IUser user, ValErrWebMessage webm, FidoAuthenticatorResponse response)
        {
            if (!ResponseValidator.Validate(response, webm))
            {
                return;
            }

            bool isAlgSupported = _supportedAlgs.Any(p => p.AlgId == response.CoseAlgorithmNumber);

            if (webm.Assert(isAlgSupported, "Authenticator does not support the same algorithms as the server"))
            {
                return;
            }

            FidoClientDataJson? clientData = Base64Util.DeserializeJson<FidoClientDataJson>(response.Base64ClientData!);

            if (webm.Assert(clientData != null, "Client data json is not valid"))
            {
                return;
            }

            if (!ClientDataValidator.Validate(clientData, webm))
            {
                return;
            }

            if (webm.Assert(user.FidoCanAddKey(), "You cannot add another fido security key, limit reached"))
            {
                return;
            }

            FidoDeviceCredential cred;

            //Ensure the authenticator data is valid (signature matches public key and auth data)
            if (webm.Assert(FidoDecoder.ValidateResponse(response, out cred), "Your device's signature is not valid"))
            {
                return;
            }

            //Add key data to the user's data store
            user.FidoAddCredential(cred);

            webm.Result = "Your fido device was successfully added to your account";
            webm.Success = true;
        }

        private static void DeleteSingleDeviceAsync(IUser user, WebMessage webm, string? deviceId)
        {
            if (webm.Assert(!string.IsNullOrWhiteSpace(deviceId), "You must specify a valid device id"))
            {
                return;
            }

            //Remove the device
            user.FidoRemoveCredential(deviceId);

            webm.Result = "Successfully removed your fido device";
            webm.Success = true;
        }
      

        private static FidoDeviceCredential? GetSelectedDevice(IUser user, FidoUpgradeResponse response)
        {
            //Get the device the user used to log in with 

            return user.FidoGetAllCredentials()
                ?.FirstOrDefault(p => string.Equals(
                    p.Base64DeviceId,
                    response.Base64UrlId,
                    StringComparison.OrdinalIgnoreCase
                ));
        }

        private static bool CheckChallengeMatches(FidoConfig config, JsonElement request, FidoClientDataJson clientData)
        {
            /*
             * When this function is called it must be assumed that the mfa token signature
             * was verified so it doesn't need to be checked again. 
             * 
             * The only data we need to recover from the upgrade is the fido challenge data.
             * 
             * Since the client passes the challenge back, we just need to make sure the 
             * challnge matches because the signature will be verified over the entire
             * auth data json object so we don't need to reconstruct it and save us 
             * some computation cycles.
             */

            string? mfaUpgradeJwt = request.GetPropString("upgrade");
            if (string.IsNullOrWhiteSpace(mfaUpgradeJwt))
            {
                return false;
            }

            using JsonWebToken jwt = JsonWebToken.Parse(mfaUpgradeJwt);
            using JsonDocument chalDoc = jwt.GetPayload();

            /*
             * If strict origin is set, the origin of the device must match the origin
             * of the server that issued the challenge.
             */
            if (config.StrictOrigin)
            {
                //Issuer is set during upgrade, we can use it to verify the origin the device signed
                string? origin = chalDoc.RootElement.GetPropString("iss");

                if(string.Equals(origin, clientData.Origin, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            string? challenge = chalDoc.RootElement.GetProperty(JwtClaimKey)
                .GetPropString("challenge");

            return string.Equals(
                challenge, 
                clientData.Base64Challenge, 
                StringComparison.OrdinalIgnoreCase
            );
        }

        private static FidoDevUpgradeJson GetChallengeData(FidoConfig config, ReadOnlySpan<byte> challenge, FidoDeviceCredential[] devices)
        {
            return new FidoDevUpgradeJson
            {
                Base64UrlChallange = VnEncoding.Base64UrlEncode(challenge, includePadding: false),

                Timeout = config.Timeout,

                Credentials = devices.Select(p => new CredentialInfoJson
                {
                    Base64UrlId     = p.Base64DeviceId!,
                    Transports      = config.Transports,
                    Type            = "public-key"
                })
                .ToArray(),
            };
        }
     
        private static bool VerifySignedData(
            FidoAuthenticatorAssertionResponse assertion, 
            FidoDeviceCredential device
        )
        {
            /*
             * The buffer needs to be large enough to store the decided authenticator data and 
             * the hash of the client data. The hash will be appended to the end of the client data
             * and the signature will be verified over the entire buffer.
             */
            int outBuffSize = assertion.Base64UrlAuthData.Length + ManagedHash.GetHashSize(HashAlg.SHA256);
            using UnsafeMemoryHandle<byte> clientDataBuffer = MemoryUtil.UnsafeAlloc<byte>(outBuffSize + 16);

            ForwardOnlyWriter<byte> writer = new(clientDataBuffer.Span);

            if (!ReadAuthData(ref writer, assertion.Base64UrlAuthData))
            {
                return false;
            }

            //Get the signed data and write it to the buffer
            if (!BuildSignedDataBuffer(ref writer, assertion.Base64UrlClientData))
            {
                return false;
            }

            //Verify the signature over the signed data
            return VerifySignature(
                device, 
                signedData: writer.AsSpan(),
                assertion.Base64UrlSignature
            );
        }

        private static bool ReadAuthData(ref ForwardOnlyWriter<byte> outputBuffer, string authenticatorData)
        {
            ERRNO authSize = VnEncoding.Base64UrlDecode(authenticatorData, outputBuffer.Remaining);

            //Advance the output buffer to the end of the auth data since it's appended first
            outputBuffer.Advance(authSize);
            return authSize;
        }
       
        private static bool BuildSignedDataBuffer(ref ForwardOnlyWriter<byte> outputBuffer, string base64ClientData)
        {
            using UnsafeMemoryHandle<byte> clientDataBuffer = MemoryUtil.UnsafeAlloc<byte>(base64ClientData.Length + 16);
          
            ERRNO clientDataSize = VnEncoding.Base64UrlDecode(base64ClientData, clientDataBuffer.Span);

            if(clientDataSize <= 0)
            {
                return false;
            }

            //Write the hash directly following the auth data
            ERRNO hashBytes = ManagedHash.ComputeHash(
                data: clientDataBuffer.AsSpan(0, clientDataSize),
                output: outputBuffer.Remaining,
                HashAlg.SHA256
            );

            outputBuffer.Advance(hashBytes);
            return hashBytes;
        }

        private static bool VerifySignature(FidoDeviceCredential device, ReadOnlySpan<byte> signedData, string base64Signature)
        {
            using UnsafeMemoryHandle<byte> signatureBuffer = MemoryUtil.UnsafeAlloc<byte>(base64Signature.Length + 16);
            ERRNO size = VnEncoding.Base64UrlDecode(base64Signature, signatureBuffer.Span);

            if (size <= 0)
            {
                return false;
            }

            //Recover signing alg for the selected device
            using ECDsa alg = GetSigAlgForDevice(device);

            return alg.VerifyData(
                data: signedData, 
                signature: signatureBuffer.AsSpan(0, size), 
                hashAlgorithm: HashAlg.SHA256.GetAlgName(),
                DSASignatureFormat.Rfc3279DerSequence
            );
        }

        private static ECDsa GetSigAlgForDevice(FidoDeviceCredential device)
        {
            ECParameters p = new()
            {
                Curve = CoseEncodings.GetECCurveFromCode(device.CoseAlgId),

                Q = new()
                {
                    X = Base64Util.DecodeArray(device.Base64XCoord!),
                    Y = Base64Util.DecodeArray(device.Base64YCoord!)
                }
            };

            return ECDsa.Create(p);
        }

        private sealed class UserGetResult
        {
            [JsonPropertyName("devices")]
            public FidoDeviceCredential[]? Devices { get; set; }

            [JsonPropertyName("can_add_devices")]
            public bool? CanAddDevices { get; set; }

            [JsonPropertyName("data_size")]
            public int? DataSize { get; set; }

            [JsonPropertyName("max_size")]
            public int? MaxSize { get; set; }
        }

        private sealed class FidoRequestMessage() : PrivateStringManager(1)
        {
            [JsonPropertyName("password")]
            public string? Password
            {
                get => this[0];
                set => this[0] = value;
            }

            [JsonPropertyName("action")]
            public string? Action { get; set; }

            [JsonPropertyName("device_id")]
            public string? DeviceId { get; set; }

            [JsonPropertyName("registration")]
            public FidoAuthenticatorResponse? Registration { get; set; }
        }

        private sealed class FidoMessageValidator : AbstractValidator<FidoRequestMessage>
        {
            public FidoMessageValidator()
            {
                RuleFor(p => p.Action!)
                    .NotEmpty()
                    .WithMessage("Action must be provided")
                    .Matches(@"^(prepare_device|register_device|disable_device|disable_all)$");

                //Standard resource exhuastion protection (large passwords take time to hash)
                RuleFor(p => p.Password)
                    .MaximumLength(200);
            }
        }

        private sealed class FidoAuthValidator : AbstractValidator<FidoUpgradeResponse>
        {
            public FidoAuthValidator()
            {
                RuleFor(p => p.Response)
                    .NotNull()
                    .ChildRules(val =>
                    {
                        val.RuleFor(p => p!.Base64UrlAuthData)
                            .NotEmpty()
                            .Matches(@"^[a-zA-Z0-9_-]{1,512}$");

                        val.RuleFor(p => p!.Base64UrlClientData)
                            .NotEmpty()
                            .Matches(@"^[a-zA-Z0-9_-]{1,512}$");

                        val.RuleFor(p => p!.Base64UrlSignature)
                            .NotEmpty()
                            .Matches(@"^[a-zA-Z0-9_-]{1,512}$");
                    });

                //Device id must be a valid base64 url string
                RuleFor(p => p.Base64UrlId)
                    .NotEmpty()
                    .Matches(@"^[a-zA-Z0-9_-]{1,128}$");
            }
        }
    }
}
