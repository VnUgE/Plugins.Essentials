/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth.ClientApps
* File: ApplicationEndpoint.cs 
*
* ApplicationEndpoint.cs is part of VNLib.Plugins.Essentials.Oauth.ClientApps which 
* is part of the larger VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Oauth.ClientApps is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Oauth.ClientApps is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json.Serialization;

using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Utils.Extensions;
using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Essentials.Endpoints;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Oauth.Applications;
using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Extensions.Data.Extensions;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Extensions.Loading.Users;
using static VNLib.Plugins.Essentials.Statics;


namespace VNLib.Plugins.Essentials.Oauth.ClientApps.Endpoints
{

    [EndpointPath("{{path}}")]
    [EndpointLogName("Applications")]
    [ConfigurationName("applications")]
    internal sealed class ApplicationEndpoint : ProtectedWebEndpoint
    {

        private readonly ApplicationStore Applications;
        private readonly int MaxAppsPerUser;
        private readonly string MaxAppOverloadMessage;
        private readonly IUserManager Users;

        private static readonly UserAppValidator Validator = new();

        public ApplicationEndpoint(PluginBase plugin, IConfigScope config)
        {
            MaxAppsPerUser = config.GetRequiredProperty<int>("max_apps_per_user");

            Users = plugin.GetOrCreateSingleton<UserManager>();

            Applications = new(
                conextOptions: plugin.GetContextOptions(),
                secretHashing: Users.GetHashProvider() ?? throw new InvalidOperationException("Hash provider not loaded")
            );

            //Complie overload message
            MaxAppOverloadMessage = $"You have reached the limit of {MaxAppsPerUser} applications, this application cannot be created";
        }

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity ev)
        {
            //Try to get a single application from the database

            //Get a single specific application from an appid
            if (ev.QueryArgs.TryGetNonEmptyValue("Id", out string? appid))
            {
                appid = ValidatorExtensions.OnlyAlphaRegx.Replace(appid, string.Empty);

                //Execute get single app
                UserApplication? singeApp = await Applications.GetSingleAsync(appid, ev.Session.UserID);

                return singeApp == null ? VfReturnType.NotFound : VirtualOkJson(ev, singeApp);
            }
            //Process a "get all" 
            else
            {
                //Create list to store all applications
                List<UserApplication> applications = Applications.ListRental.Rent();
                try
                {
                    //Get all applications to fill the list
                    _ = await Applications.GetCollectionAsync(applications, ev.Session.UserID, MaxAppsPerUser, ev.EventCancellation);
                    //Write response (will convert json as needed before releasing the list)
                    return VirtualOkJson(ev, applications);
                }
                finally
                {
                    //Return the list
                    Applications.ListRental.Return(applications);
                }
            }
        }

        protected override async ValueTask<VfReturnType> PostAsync(HttpEntity entity)
        {
            //Default response
            WebMessage webm = new();
            //Oauth is only available for local accounts
            if (!entity.Session.HasLocalAccount())
            {
                webm.Result = "OAuth is only available for internal user accounts";
                return VirtualClose(entity, webm, HttpStatusCode.Forbidden);
            }

            if (entity.QueryArgs.IsArgumentSet("action", "create"))
            {
                return await CreateAppAsync(entity);
            }

            //Update the application secret
            else if (entity.QueryArgs.IsArgumentSet("action", "secret"))
            {
                using JsonDocument? update = await entity.GetJsonFromFileAsync();

                if (webm.Assert(update != null, "Invalid request"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
                }

                //Update message will include a challenge and an app id
                string? appId = update.RootElement.GetPropString("Id");

                if (webm.Assert(!string.IsNullOrWhiteSpace(appId), "Application with the specified id does not exist"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.NotFound);
                }

                //validate the user's password
                if (await ValidateUserPassword(entity, update, webm) == false)
                {
                    return VirtualClose(entity, webm, HttpStatusCode.Unauthorized);
                }

                //Update the app's secret
                using PrivateString? secret = await Applications.UpdateSecretAsync(entity.Session.UserID, appId, entity.EventCancellation);

                if (webm.Assert(secret != null, "Failed to update the application secret"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.InternalServerError);
                }

                /*
                 * We must return the secret to the user.
                 * 
                 * The PrivateString must be casted and serialized
                 * while the using statment is in scope
                 */
                ApplicationMessage result = new()
                {
                    ApplicationID = appId,
                    //Send raw secret
                    RawSecret = (string?)secret
                };

                //Must write response while password is in scope
                return VirtualOkJson(entity, result);
            }
            else if (entity.QueryArgs.IsArgumentSet("action", "delete"))
            {
                using JsonDocument? update = await entity.GetJsonFromFileAsync();

                if (webm.Assert(update != null, "Invalid request"))
                {
                    return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
                }

                //Update message will include a challenge and an app id
                string? appId = update.RootElement.GetPropString("Id");

                if (string.IsNullOrWhiteSpace(appId))
                {
                    return VfReturnType.NotFound;
                }

                //validate the password
                if (await ValidateUserPassword(entity, update, webm) == false)
                {
                    return VirtualClose(entity, webm, HttpStatusCode.Unauthorized);
                }

                //Try to delete the app
                if (await Applications.DeleteAsync(appId, entity.Session.UserID))
                {
                    return VirtualClose(entity, HttpStatusCode.NoContent);
                }
            }
            else
            {
                webm.Result = "The update type specified is not defined";
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }
            return VfReturnType.BadRequest;
        }

        protected override async ValueTask<VfReturnType> PutAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            //Oauth is only available for local accounts
            if (!entity.Session.HasLocalAccount())
            {
                webm.Result = "OAuth is only available for internal user accounts";
                return VirtualClose(entity, webm, HttpStatusCode.Forbidden);
            }

            //Get the application from client
            UserApplication? app = await entity.GetJsonFromFileAsync<UserApplication>(SR_OPTIONS);

            if (webm.Assert(app != null, "Application is empty"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //set user-id 
            app.UserId = entity.Session.UserID;
            //remove permissions
            app.Permissions = null;

            //perform validation on the application update (should remove unused fields)
            if (!Validator.Validate(app, webm))
            {
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            //Update the app's meta
            if (await Applications.UpdateAsync(app))
            {
                //Send the app to the client
                return VirtualClose(entity, HttpStatusCode.NoContent);
            }

            //The app was not found and could not be updated
            return VfReturnType.NotFound;
        }

        private async ValueTask<VfReturnType> CreateAppAsync(HttpEntity entity)
        {
            WebMessage webm = new();

            //Get the application from client
            UserApplication? newApp = await entity.GetJsonFromFileAsync<UserApplication>(SR_OPTIONS);

            if (webm.Assert(newApp != null, "Application is empty"))
            {
                return VirtualClose(entity, webm, HttpStatusCode.BadRequest);
            }

            //Validate the new application
            if (!Validator.Validate(newApp, webm))
            {
                return VirtualClose(entity, webm, HttpStatusCode.UnprocessableEntity);
            }

            //If no premissions are specified, set to "none"
            if (string.IsNullOrWhiteSpace(newApp.Permissions))
            {
                newApp.Permissions = "none";
            }

            //See if the user has enough room for more apps
            long appCount = await Applications.GetCountAsync(entity.Session.UserID, entity.EventCancellation);

            if (appCount == -1)
            {
                webm.Result = $"There was a server error during creation of your application";
                Log.Error("There was an error retreiving the number of applications for user {id}", entity.Session.UserID);
                return VirtualClose(entity, webm, HttpStatusCode.InternalServerError);
            }
            if (webm.Assert(appCount < MaxAppsPerUser, MaxAppOverloadMessage))
            {
                return VirtualOk(entity, webm);
            }
           
            //Set user-id
            newApp.UserId = entity.Session.UserID;

            //Create the new application
            if (!await Applications.CreateAppAsync(newApp))
            {
                webm.Result = "The was an issue creating your application";
                return VirtualClose(entity, webm, HttpStatusCode.InternalServerError);
            }

            //Make sure to dispose the secret once leaving function scope
            using PrivateString secret = newApp.RawSecret!;

            //Success, now respond to the client with the new app information
            ApplicationMessage mess = new()
            {
                ApplicationID   = newApp.Id,
                ApplicationName = newApp.AppName,
                RawSecret       = (string)secret,
                ClientID        = newApp.ClientId,
                Description     = newApp.AppDescription,
                Permissions     = newApp.Permissions,
                CreatedTime     = newApp.Created.ToString("O"),
                LastUpdatedTime = newApp.LastModified.ToString("O")
            };

            //Must write response while the secret is in scope
            return VirtualCloseJson(entity, mess, HttpStatusCode.Created);
        }

        private async Task<bool> ValidateUserPassword(HttpEntity entity, JsonDocument request, WebMessage webm)
        {
            //Get password from request and capture it as a private string
            using PrivateString? rawPassword = PrivateString.ToPrivateString(request.RootElement.GetPropString("password"), true);

            if (webm.Assert(rawPassword != null, "Please enter your account password"))
            {
                //Must sent a 401 to indicate that the password is required
                return false;
            }

            //Get the current user from the store
            using IUser? user = await Users.GetUserFromIDAsync(entity.Session.UserID, entity.EventCancellation);

            if (webm.Assert(user != null, "Please check your password"))
            {
                return false;
            }

            //Validate the password against the user
            bool isPasswordValid = await Users.ValidatePasswordAsync(user, rawPassword, PassValidateFlags.None, entity.EventCancellation) == UserPassValResult.Success;

            return !webm.Assert(isPasswordValid, "Please check your password");
        }

        private sealed class ApplicationMessage
        {
            [JsonPropertyName("name")]
            public string? ApplicationName { get; set; }

            [JsonPropertyName("description")]
            public string? Description { get; set; }

            [JsonPropertyName("client_id")]
            public string? ClientID { get; set; }

            [JsonPropertyName("raw_secret")]
            public string? RawSecret { get; set; }

            [JsonPropertyName("Id")]
            public string? ApplicationID { get; set; }

            [JsonPropertyName("permissions")]
            public string? Permissions { get; set; }

            [JsonPropertyName("Created")]
            public string? CreatedTime { get; set; }

            [JsonPropertyName("LastModified")]
            public string? LastUpdatedTime { get; set; }
        }

    }
}