/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: MFAEndpoint.cs 
*
* MFAEndpoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Essentials.Accounts.MFA.Otp;
using VNLib.Plugins.Essentials.Accounts.MFA.Totp;
using VNLib.Plugins.Essentials.Accounts.MFA.Fido;

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{

    [ConfigurationName("mfa_endpoint")]
    internal sealed class MFAEndpoint : ProtectedWebEndpoint
    {
        public const int TOTP_URL_MAX_CHARS = 1024;
        private const string CHECK_PASSWORD = "Please check your password";

        private readonly IUserManager Users;
        private readonly MFAConfig MultiFactor;

        public MFAEndpoint(PluginBase pbase, IConfigScope config)
        {           
            InitPathAndLog(
                path: config.GetRequiredProperty("path", p => p.GetString()!), 
                log: pbase.Log.CreateScope("Mfa-Endpoint")
            );

            Users = pbase.GetOrCreateSingleton<UserManager>();
            MultiFactor = pbase.GetConfigElement<MFAConfig>();
        }

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            string[] enabledModes = new string[3];

            //Load the MFA entry for the user
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);
           
            if (user?.TotpEnabled() == true)
            {
                enabledModes[0] = "totp";
            }
          
            if (user?.FidoEnabled() == true)
            {
                enabledModes[1] = "fido";
            }
          
            if (user?.OtpAuthEnabled() == true)
            {
                enabledModes[2] = "pki";
            }

            //Return mfa modes as an array
            return VirtualOkJson(entity, enabledModes);
        }

        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            //Get the request message
            using JsonDocument? mfaRequest = await entity.GetJsonFromFileAsync();

            if (webm.Assert(mfaRequest != null, "Invalid request"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }
            
            //Get the type argument
            string? mfaType = mfaRequest.RootElement.GetPropString("type");
            if (string.IsNullOrWhiteSpace(mfaType))
            {
                webm.Result = "MFA type was not specified";
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }
            
            //Make sure the user's account origin is a local account
            if (webm.Assert(entity.Session.HasLocalAccount(), "Your account uses external authentication and MFA cannot be enabled"))
            {
                return VirtualOk(entity, webm);
            }

            //Get the user entry
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);

            if (webm.Assert(user != null, "Please log-out and try again."))
            {
                return VirtualOk(entity, webm);
            }

            //get the user's password challenge
            using (PrivateString? password = (PrivateString?)mfaRequest.RootElement.GetPropString("password"))
            {
                if (webm.Assert(!PrivateString.IsNullOrEmpty(password), CHECK_PASSWORD))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.Unauthorized);
                }

                //Verify password against the user
                ERRNO result = await Users.ValidatePasswordAsync(user, password, PassValidateFlags.None, entity.EventCancellation);

                if (webm.Assert(result > 0, CHECK_PASSWORD))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.Unauthorized);
                }
            }

            switch (mfaType.ToLower(null))
            {
                //Process a Time based one time password(TOTP) creation/regeneration
                case "totp":
                    {
                        //Confirm totp is enabled
                        if (webm.Assert(MultiFactor.TOTPEnabled, "TOTP is not enabled on the current server"))
                        {
                            return VirtualOk(entity, webm);
                        }

                        //Update TOTP secret for user
                        await UpdateUserTotp(entity, user, webm);
                    }
                    break;
                default:
                    webm.Result = "The server does not support the specified MFA type";
                    break;
            }
            //Close response
            return VirtualOk(entity, webm);
        }

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            try
            {
                //Check account type
                if (webm.Assert(entity.Session.HasLocalAccount(), "You are using external authentication. Operation failed."))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
                }
                
                //get the request
                using JsonDocument? request = await entity.GetJsonFromFileAsync();
                if (webm.Assert(request != null, "Invalid request"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
                }
             
                string? mfaType = request.RootElement.GetProperty("type").GetString();
              
                using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);

                if (webm.Assert(user != null, "User does not exist"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.NotFound);
                }

                /*
                 * An MFA upgrade requires a challenge to be verified because
                 * it can break the user's ability to access their account
                 */
                using (PrivateString? password = (PrivateString?)request.RootElement.GetPropString("password"))
                {
                    if (webm.Assert(!PrivateString.IsNullOrEmpty(password), CHECK_PASSWORD))
                    {
                        return VirtualClose(entity, webm, HttpStatusCode.Unauthorized);
                    }

                    //Verify password against the user
                    ERRNO result = await Users.ValidatePasswordAsync(user, password, PassValidateFlags.None, entity.EventCancellation);
                   
                    if (webm.Assert(result > 0, CHECK_PASSWORD))
                    {
                        return VirtualClose(entity, webm, HttpStatusCode.Unauthorized);
                    }
                }

                //Check for totp disable
                if (string.Equals("totp", mfaType, StringComparison.OrdinalIgnoreCase))
                {
                    user.TotpDisable();
                  
                    webm.Result = "Successfully disabled your TOTP authentication";
                    webm.Success = true;
                }
                else if (string.Equals("fido", mfaType, StringComparison.OrdinalIgnoreCase))
                {
                    user.FidoDisable();
                    
                    webm.Result = "Successfully disabled your FIDO authentication";
                    webm.Success = true;
                }
                else if(string.Equals("pkotp", mfaType, StringComparison.OrdinalIgnoreCase))
                {
                    user.OtpDisable();
                    
                    webm.Result = "Successfully disabled your OTP authentication";
                    webm.Success = true;
                }
                else
                {
                    webm.Result = "Invalid MFA type";
                }

                //write changes (will do nothing if no changes were made)
                await user.ReleaseAsync();

                //Must write response while password is in scope
                return VirtualOk(entity, webm);
            }
            catch (KeyNotFoundException)
            {
                webm.Result = "The request was is missing required fields";
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }
        }

        private async Task UpdateUserTotp(HttpEntity entity, IUser user, WebMessage webm)
        {
            //generate a new secret (passing the buffer which will get copied to an array because the pw bytes can be modified during encryption)
            byte[] secretBuffer = user.MFAGenreateTOTPSecret(MultiFactor);
            //Alloc output buffer
            IMemoryHandle<byte> outputBuffer = MemoryUtil.SafeAlloc(4096, true);

            try
            {
                //Encrypt the secret for the client
                ERRNO count = entity.TryEncryptClientData(secretBuffer, outputBuffer.Span);

                if (!count)
                {
                    webm.Result = "There was an error updating your credentials";

                    //If this code is running, the client should have a valid public key stored, but log it anyway
                    Log.Warn("TOTP secret encryption failed, for requested user {uid}", entity.Session.UserID);
                }
                else
                {
                    webm.Result = new TOTPUpdateMessage()
                    {
                        Issuer = MultiFactor.TOTPConfig.IssuerName,
                        Digits = MultiFactor.TOTPConfig.TOTPDigits,
                        Period = (int)MultiFactor.TOTPConfig.TOTPPeriod.TotalSeconds,
                        Algorithm = MultiFactor.TOTPConfig.TOTPAlg.ToString(),
                        //Convert the secret to base64 string to send to client
                        Base64EncSecret = Convert.ToBase64String(outputBuffer.Span[..(int)count])
                    };

                    //set success flag
                    webm.Success = true;

                    //Only write changes to the db of operation was successful
                    await user.ReleaseAsync();
                }
            }
            finally
            {
                //dispose the output buffer
                outputBuffer.Dispose();
                MemoryUtil.InitializeBlock(secretBuffer);
            }
        }

        private class TOTPUpdateMessage
        {
            [JsonPropertyName("issuer")]
            public string? Issuer { get; set; }
            [JsonPropertyName("digits")]
            public int Digits { get; set; }
            [JsonPropertyName("period")]
            public int Period { get; set; }
            [JsonPropertyName("secret")]
            public string? Base64EncSecret { get; set; }
            [JsonPropertyName("algorithm")]
            public string? Algorithm { get; set; }
        }
    }
}