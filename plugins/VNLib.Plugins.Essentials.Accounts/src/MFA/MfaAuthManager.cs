/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MfaAuthManager.cs 
*
* MfaAuthManager.cs is part of VNLib.Plugins.Essentials.Accounts which is 
* part of the larger VNLib collection of libraries and utilities.
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
using System.Collections.Generic;

using FluentValidation;

using VNLib.Utils;
using VNLib.Hashing;
using VNLib.Hashing.IdentityUtility;
using VNLib.Utils.Memory;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Sessions;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.MFA
{

    internal sealed class MfaAuthManager(MFAConfig config)
    {

        public const string SESSION_SIG_KEY = "mfa.sig";
        private const HashAlg SigAlg = HashAlg.SHA256;     
        
        private readonly IMfaProcessor[] processors = config.GetSupportedProcessors();
        private readonly byte[] UpgradeHeader = CompileJwtHeader();

        public MfaAuthManager(PluginBase plugin) : this(plugin.GetConfigElement<MFAConfig>())
        { }

        public bool Armed => processors.Length > 0;

        /// <summary>
        /// Gets the MFA processors available for use
        /// </summary>
        public IEnumerable<IMfaProcessor> Processors => processors;

        /// <summary>
        /// Gets the MFA configuration settings
        /// </summary>
        public MFAConfig Config => config;

        /// <summary>
        /// Determines if the user has any MFA methods enabled and 
        /// should continue with an MFA upgrade
        /// </summary>
        /// <param name="user">The user to upgrade the mfa request on</param>
        /// <returns>True if the user has any MFA methods enabled</returns>
        public bool HasMfaEnabled(IUser user) => processors.Any(p => p.MethodEnabledForUser(user));

        /// <summary>
        /// Gets the upgrade message to send back to the client to 
        /// continue the MFA upgrade process
        /// </summary>
        /// <param name="entity">The connection to upgrade</param>
        /// <param name="user">The user wishing to upgrade MFA methods</param>
        /// <param name="login">The login message containing required client authentication data</param>
        /// <returns>The encoded upgrade message to send to the client</returns>
        public string GetChallengeMessage(HttpEntity entity, IUser user, LoginMessage login)
        {
            string clientJwt = string.Empty, secret = string.Empty;

            /*
             * Upgrade tells the client what methods are suppoted by 
             * the server specific to a user. The client may choose 
             * to use any of the methods.
             */
            MfaChallenge upgrade = new()
            {
                //Set totp upgrade type
                Types = GetEnbaledTypesForUser(user),

                //Store login message details
                UserName = login.UserName,
                ClientId = login.ClientId,
                PublicKey = login.ClientPublicKey,
                ClientLocalLanguage = login.LocalLanguage,
            };

            GetUpgradeMessage(upgrade, ref clientJwt, ref secret);

            //Store the upgrade message in the session
            SetUpgradeSecret(in entity.Session, secret);

            return clientJwt;
        }

        /// <summary>
        /// Recovers and validates a previously signed challenge message from the client
        /// </summary>
        /// <param name="entity">The entity requesting the completation</param>
        /// <param name="result">The client's result of an mfa upgrade operation</param>
        /// <returns>The </returns>
        public MfaChallenge? GetChallengeData(HttpEntity entity, JsonDocument result)
        {
            //Recover upgrade jwt
            string? upgradeJwt = result.RootElement.GetPropString("upgrade");
            string? storedSecret = GetUpgradeSecret(in entity.Session);

            if (string.IsNullOrEmpty(upgradeJwt) || string.IsNullOrEmpty(storedSecret))
            {
                return null;
            }

            //Recover upgrade data from upgrade message
            return RecoverChallange(entity.RequestedTimeUtc, upgradeJwt, storedSecret);
        }

        /// <summary>
        /// Verifies the response from the client to the MFA upgrade request
        /// and determines if the upgrade was successful
        /// </summary>
        /// <param name="entity"></param>
        /// <param name="upgrade">The validated upgrade message returned by the client</param>
        /// <param name="user">The user account to validate against</param>
        /// <param name="result">The client's result message from the upgrade challenge</param>
        /// <returns>True if the client successfully validated</returns>
        public bool VerifyResponse(HttpEntity entity, MfaChallenge upgrade, IUser user, JsonDocument result)
        {
            string? desiredMfaType = entity.QueryArgs.GetValueOrDefault("mfa");

            if (!Enum.TryParse(desiredMfaType, true, out MFAType desiredType))
            {
                return false;
            }

            //See if upgrade allows the desired type
            if (!upgrade.Types.Contains(desiredType))
            {
                return false;
            }

            //Get the processor for the desired type
            IMfaProcessor? processor = processors.FirstOrDefault(p => p.Type == desiredType);

            if (processor == null)
            {
                return false;
            }

            //Verify the response using the desired processor
            return processor.VerifyResponse(upgrade, user, result);
        }

        public void InvalidateUpgrade(HttpEntity entity) 
            => SetUpgradeSecret(in entity.Session, null);

        private MFAType[] GetEnbaledTypesForUser(IUser user)
        {
            return processors.Where(p => p.MethodEnabledForUser(user))
                .Select(static p => p.Type)
                .ToArray();
        }

        private static void SetUpgradeSecret(ref readonly SessionInfo session, string? base32Signature) 
            => session[SESSION_SIG_KEY] = base32Signature!;

        private static string? GetUpgradeSecret(ref readonly SessionInfo session)
            => session[SESSION_SIG_KEY];

        private MfaChallenge? RecoverChallange(DateTimeOffset now, string upgradeJwtString, string base32Secret)
        {           
            using JsonWebToken jwt = JsonWebToken.Parse(upgradeJwtString);
            
            byte[] secret = VnEncoding.FromBase32String(base32Secret)!;
            
            try
            {
                if (!jwt.Verify(secret, SigAlg))
                {
                    return null;
                }
            }
            finally
            {
                //Erase secret
                MemoryUtil.InitializeBlock(secret);
            }
          
            using JsonDocument doc = jwt.GetPayload();

            //Recover issued at time
            long iatMs = doc.RootElement.GetProperty("iat").GetInt64();
            DateTimeOffset iat = DateTimeOffset.FromUnixTimeMilliseconds(iatMs);

            if (iat.Add(config.UpgradeValidFor) < now)
            {
                //expired
                return null;
            }

            //Recover the upgrade message
            return doc.RootElement.GetProperty("upgrade")
                .Deserialize<MfaChallenge>();
        }

        private void GetUpgradeMessage(MfaChallenge upgrade, ref string clientMessage, ref string secret)
        {
            //Add some random entropy to the upgrade message, to help prevent forgery
            string entropy = RandomHash.GetRandomBase32(config.NonceLenBytes);
            byte[] sigKey = RandomHash.GetRandomBytes(config.UpgradeKeyBytes);

            using JsonWebToken upgradeJwt = new();
        
            upgradeJwt.WriteHeader(UpgradeHeader);
          
            string[] mfaTypes = upgrade.Types.Select(static t => t.ToString().ToLower(null)).ToArray();

            upgradeJwt.InitPayloadClaim()
                .AddClaim("iat", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                .AddClaim("upgrade", upgrade)
                .AddClaim("capabilities", mfaTypes)
                .AddClaim("expires", config.UpgradeValidFor.TotalSeconds)
                .AddClaim("a", entropy)
                .CommitClaims();
            
            upgradeJwt.Sign(sigKey, SigAlg);

            clientMessage = upgradeJwt.Compile();
            secret = VnEncoding.ToBase32String(sigKey);
        }

        private static byte[] CompileJwtHeader()
        {
            Dictionary<string, string> header = new()
            {
                { "alg","HS256" },
                { "typ", "JWT" }
            };
            return JsonSerializer.SerializeToUtf8Bytes(header);
        }
    }
}