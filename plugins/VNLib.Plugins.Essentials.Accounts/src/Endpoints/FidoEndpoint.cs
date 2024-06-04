/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: FidoEndpoint.cs 
*
* FidoEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
* VNLib collection of libraries and utilities.
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
using System.Net;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

using FluentValidation;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Hashing;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Extensions;

using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Essentials.Accounts.MFA.Fido;


namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    /// <summary>
    /// <para>
    /// This enpdoint requires Fido to be enabled in the MFA configuration.
    /// </para>
    /// </summary>
    [ConfigurationName("fido_endpoint")]
    internal sealed class FidoEndpoint : ProtectedWebEndpoint
    {
        private static readonly FidoResponseValidator ResponseValidator = new();
        private static readonly FidoClientDataJsonValidtor ClientDataValidator = new();

        private readonly IUserManager _users;
        private readonly FidoConfig _fidoConfig;
        private readonly FidoPubkeyAlgorithm[] _supportedAlgs;

        public FidoEndpoint(PluginBase plugin, IConfigScope config)
        {
            _users = plugin.GetOrCreateSingleton<UserManager>();
            _fidoConfig = plugin.GetConfigElement<MFAConfig>().FIDOConfig
                ?? throw new ConfigurationValidationException("Fido configuration was not set, but Fido endpoint was enabled");

            InitPathAndLog(
                path: config.GetRequiredProperty("path", p => p.GetString()!), 
                log: plugin.Log.CreateScope("Fido-Endpoint")
            );

            /*
             * For now hard-code supported algorithms,
             * ECDSA is easiest for the time being
             */

            _supportedAlgs =
            [
                new FidoPubkeyAlgorithm(algId: -7),    //ES256
                new FidoPubkeyAlgorithm(algId: -35),   //ES384     
                new FidoPubkeyAlgorithm(algId: -36),   //ES512
            ];
        }

        protected override VfReturnType Get(HttpEntity entity)
        {
            return VirtualOk(entity);
        }

        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();

            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            if (webm.Assert(user != null, "User not found"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.NotFound);
            }

            if(webm.Assert(user.FidoCanAddKey(), "You cannot add another key to this account. You must delete an existing one first"))
            {
                return VirtualOk(entity, webm);
            }

            //TODO: Store challenge in user session
            string challenge = RandomHash.GetRandomBase64(16);

            webm.Result = new FidoRegistrationMessage
            {
                AttestationType = _fidoConfig.AttestationType,
                AuthSelection = _fidoConfig.FIDOAuthSelection,
                RelyingParty = new FidoRelyingParty
                {
                    Id = entity.Server.RequestUri.DnsSafeHost,
                    Name = _fidoConfig.SiteName
                },
                User = new FidoUserData
                {
                    UserId = user.UserID,
                    UserName = user.EmailAddress,
                    DisplayName = user.EmailAddress,
                },
                Timeout = _fidoConfig.Timeout,
                PubKeyCredParams = _supportedAlgs,
                Base64Challenge = challenge,
            };

            webm.Success = true;

            return VirtualOk(entity, webm);
        }

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            ValErrWebMessage webm = new();

            using JsonDocument? doc = await entity.GetJsonFromFileAsync();

            if(webm.Assert(doc != null, "Missing entity message"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            /*
             * Handle a registration response from the client that is used to 
             * register a new credential to the user's account
             */

            if (doc.RootElement.TryGetProperty("registration", out JsonElement deviceResponse))
            {
                //complete registation of new device
                FidoAuthenticatorResponse? res = deviceResponse.Deserialize<FidoAuthenticatorResponse>();

                if(webm.Assert(res != null, "Mising registation response object"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
                }

                if(!ResponseValidator.Validate(res, webm))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
                }

                return await RegisterDeviceAsync(entity, res);
            }

            return VfReturnType.NotFound;           
        }

        private async ValueTask<VfReturnType> RegisterDeviceAsync(
            HttpEntity entity, 
            FidoAuthenticatorResponse response
        )
        {
            ValErrWebMessage webm = new();

            bool isAlgSupported = _supportedAlgs.Any(p => p.AlgId == response.CoseAlgorithmNumber);
          
            if(webm.Assert(isAlgSupported, "Authenticator does not support the same algorithms as the server"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            FidoClientDataJson? clientData = FidoBase64Util.DeserialzeJson<FidoClientDataJson>(response.Base64ClientData!);

            if(webm.Assert(clientData != null, "Client data json is not valid"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            if(!ClientDataValidator.Validate(clientData, webm))
            {
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            FidoDeviceCredential? cred = FidoDecoder.FromResponse(response);

            if (webm.Assert(cred != null, "Your device did not send valid public key data"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            Log.Information("Adding new credential\n {cred}", cred);

            using IUser? user = await _users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            if(webm.Assert(user != null, "User not found"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.NotFound);
            }

            if (webm.Assert(user.FidoCanAddKey(), "You cannot add another key to your account, you must delete an existing one"))
            {
                return VirtualOk(entity, webm);
            }

            //user.FidoAddCredential(cred);

            webm.Result = "Your fido device was successfully added to your account";
            webm.Success = true;

            return VirtualOk(entity, webm);
        }
       
    }

    internal sealed class FidoBase64Util
    {

        /// <summary>
        /// Takes a base64url encoded JSON string and deserializes it into a 
        /// given object.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="base64Url">The base64url encoded JSON string to decode</param>
        /// <returns>The instance of the object if it could be decoded</returns>
        /// <exception cref="JsonException"></exception>
        public static T? DeserialzeJson<T>(string base64Url)
        {
            /*
             * We just need to transform the base64 encoded chars back to 
             * utf8 bytes and then deserialize the object
             * 
             * The length is assumed to be validated before deserialization
             */

            using UnsafeMemoryHandle<byte> buffer = MemoryUtil.UnsafeAllocNearestPage(base64Url.Length);

            ERRNO count = VnEncoding.Base64UrlDecode(base64Url, buffer.Span, System.Text.Encoding.UTF8);

            if (count < 1)
            {
                throw new JsonException("Failed to decode base64url");
            }

            return JsonSerializer.Deserialize<T>(buffer.AsSpan(0, count));
        }
    }

    internal sealed class FidoResponseValidator : AbstractValidator<FidoAuthenticatorResponse>
    {
        public FidoResponseValidator()
        {
            RuleFor(c => c.DeviceId)
                .NotEmpty()
                .WithMessage("Fido 'device_id' must be provided")
                .MaximumLength(256);

            RuleFor(c => c.DeviceName)
                .NotEmpty()
                .Matches(@"^[a-zA-Z0-9\s]+$")
                .WithMessage("Your device name contains invalid characters")
                .MaximumLength(64);

            RuleFor(c => c.Base64PublicKey)
                .NotEmpty()
                .WithMessage("Fido 'public_key' must be provided");

            RuleFor(c => c.CoseAlgorithmNumber)
                .NotNull()
                .WithMessage("Fido 'public_key_algorithm' number must be provided in a valid COSE algorithm number");

            RuleFor(c => c.Base64ClientData)
                .NotEmpty()
                .WithMessage("Fido 'client_data' must be provided")
                .MaximumLength(4096);

            RuleFor(c => c.Base64AuthenticatorData)
                .NotEmpty()
                .WithMessage("Fido 'authenticator_data' must be provided")
                .MaximumLength(4096);

            RuleFor(c => c.Base64Attestation)
                .NotEmpty()
                .WithMessage("Fido 'attestation' must be provided")
                .MaximumLength(4096);
        
        }

    }
    
    internal sealed class FidoClientDataJsonValidtor : AbstractValidator<FidoClientDataJson>
    {
        public FidoClientDataJsonValidtor()
        {
            RuleFor(c => c.Base64Challenge)
                .NotEmpty()
                .WithMessage("Fido 'challenge' is required")
                .MaximumLength(4096);

            RuleFor(c => c.Origin)
                .NotEmpty()
                .WithMessage("Fido 'origin' is required")
                .MaximumLength(1024);

            RuleFor(c => c.Type)
                .NotEmpty()
                .WithMessage("Fido 'type' must be provided")
                .Matches("webauthn.create");
        }
    }
}