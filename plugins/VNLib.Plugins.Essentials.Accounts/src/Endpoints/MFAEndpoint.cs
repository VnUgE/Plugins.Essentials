/*
* Copyright (c) 2023 Vaughn Nugent
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

namespace VNLib.Plugins.Essentials.Accounts.Endpoints
{
    [ConfigurationName("mfa_endpoint")]
    internal sealed class MFAEndpoint : ProtectedWebEndpoint
    {
        public const int TOTP_URL_MAX_CHARS = 1024;

        private readonly IUserManager Users;
        private readonly MFAConfig? MultiFactor;
        private readonly IPasswordHashingProvider Passwords;

        public MFAEndpoint(PluginBase pbase, IConfigScope config)
        {
            string? path = config["path"].GetString();
            InitPathAndLog(path, pbase.Log);

            Users = pbase.GetOrCreateSingleton<UserManager>();
            MultiFactor = pbase.GetConfigElement<MFAConfig>();
            Passwords = pbase.GetPasswords();
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

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {
            List<string> enabledModes = new(2);

            //Load the MFA entry for the user
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);

            //Set the TOTP flag if set
            if (!string.IsNullOrWhiteSpace(user?.MFAGetTOTPSecret()))
            {
                enabledModes.Add("totp");
            }

            //TODO Set fido flag if enabled
            if (!string.IsNullOrWhiteSpace(""))
            {
                enabledModes.Add("fido");
            }

            //Return mfa modes as an array
            entity.CloseResponseJson(HttpStatusCode.OK, enabledModes);
            return VfReturnType.VirtualSkip;
        }

        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            //Get the request message
            using JsonDocument? mfaRequest = await entity.GetJsonFromFileAsync();

            if (webm.Assert(mfaRequest != null, "Invalid request"))
            {
                entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Get the type argument
            string? mfaType = mfaRequest.RootElement.GetPropString("type");
            if (string.IsNullOrWhiteSpace(mfaType))
            {
                webm.Result = "MFA type was not specified";
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.VirtualSkip;
            }
            
            //Make sure the user's account origin is a local account
            if (webm.Assert(entity.Session.HasLocalAccount(), "Your account uses external authentication and MFA cannot be enabled"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Make sure mfa is loaded
            if (webm.Assert(MultiFactor != null, "MFA is not enabled on this server"))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //Get the user entry
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);

            if (webm.Assert(user != null, "Please log-out and try again."))
            {
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }

            //get the user's password challenge
            using (PrivateString? password = (PrivateString?)mfaRequest.RootElement.GetPropString("password"))
            {
                if (PrivateString.IsNullOrEmpty(password))
                {
                    webm.Result = "Please check your password";
                    entity.CloseResponseJson(HttpStatusCode.Unauthorized, webm);
                    return VfReturnType.VirtualSkip;
                }

                //Verify password against the user
                if (!user.VerifyPassword(password, Passwords))
                {
                    webm.Result = "Please check your password";
                    entity.CloseResponseJson(HttpStatusCode.Unauthorized, webm);
                    return VfReturnType.VirtualSkip;
                }
            }

            switch (mfaType.ToLower())
            {
                //Process a Time based one time password(TOTP) creation/regeneration
                case "totp":
                    {
                        //Confirm totp is enabled
                        if (webm.Assert(MultiFactor.TOTPEnabled, "TOTP is not enabled on the current server"))
                        {
                            entity.CloseResponse(webm);
                            return VfReturnType.VirtualSkip;
                        }

                        //generate a new secret (passing the buffer which will get copied to an array because the pw bytes can be modified during encryption)
                        byte[] secretBuffer = user.MFAGenreateTOTPSecret(MultiFactor);
                        //Alloc output buffer
                        UnsafeMemoryHandle<byte> outputBuffer = MemoryUtil.UnsafeAlloc<byte>(4096, true);
                        
                        try
                        {
                            //Encrypt the secret for the client
                            ERRNO count = entity.TryEncryptClientData(secretBuffer, outputBuffer.Span);
                            
                            if (!count)
                            {
                                webm.Result = "There was an error updating your credentials";
                                //If this code is running, the client should have a valid public key stored, but log it anyway
                                Log.Warn("TOTP secret encryption failed, for requested user {uid}", entity.Session.UserID);
                                break;
                            }
                            
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
                        }
                        finally
                        {
                            //dispose the output buffer
                            outputBuffer.Dispose();
                            MemoryUtil.InitializeBlock(secretBuffer.AsSpan());
                        }
                        //Only write changes to the db of operation was successful
                        await user.ReleaseAsync();
                    }
                    break;
                default:
                    webm.Result = "The server does not support the specified MFA type";
                    break;
            }
            //Close response
            entity.CloseResponse(webm);
            return VfReturnType.VirtualSkip;
        }

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            WebMessage webm = new();
            try
            {
                //Check account type
                if (!entity.Session.HasLocalAccount())
                {
                    webm.Result = "You are using external authentication. Operation failed.";
                    entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                    return VfReturnType.VirtualSkip;
                }
                
                //get the request
                using JsonDocument? request = await entity.GetJsonFromFileAsync();
                if (webm.Assert(request != null, "Invalid request."))
                {
                    entity.CloseResponseJson(HttpStatusCode.BadRequest, webm);
                    return VfReturnType.VirtualSkip;
                }
             
                string? mfaType = request.RootElement.GetProperty("type").GetString();

                //get the user
                using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID);
                if (user == null)
                {
                    return VfReturnType.NotFound;
                }

                /*
                 * An MFA upgrade requires a challenge to be verified because
                 * it can break the user's ability to access their account
                 */
                using (PrivateString? password = (PrivateString?)request.RootElement.GetPropString("password"))
                {
                    if (PrivateString.IsNullOrEmpty(password))
                    {
                        webm.Result = "Please check your password";
                        entity.CloseResponseJson(HttpStatusCode.Unauthorized, webm);
                        return VfReturnType.VirtualSkip;
                    }

                    //Verify password against the user
                    if (!user.VerifyPassword(password, Passwords))
                    {
                        webm.Result = "Please check your password";
                        entity.CloseResponseJson(HttpStatusCode.Unauthorized, webm);
                        return VfReturnType.VirtualSkip;
                    }
                }

                //Check for totp disable
                if ("totp".Equals(mfaType, StringComparison.OrdinalIgnoreCase))
                {
                    //Clear the TOTP secret
                    user.MFASetTOTPSecret(null);
                    //write changes
                    await user.ReleaseAsync();
                    webm.Result = "Successfully disabled your TOTP authentication";
                    webm.Success = true;
                }
                else if ("fido".Equals(mfaType, StringComparison.OrdinalIgnoreCase))
                {
                    //Clear webauthn changes

                    //write changes
                    await user.ReleaseAsync();
                    webm.Result = "Successfully disabled your FIDO authentication";
                    webm.Success = true;
                }
                else
                {
                    webm.Result = "Invalid MFA type";
                }

                //Must write response while password is in scope
                entity.CloseResponse(webm);
                return VfReturnType.VirtualSkip;
            }
            catch (KeyNotFoundException)
            {
                webm.Result = "The request was is missing required fields";
                entity.CloseResponseJson(HttpStatusCode.UnprocessableEntity, webm);
                return VfReturnType.BadRequest;
            }
        }
    }
}