/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: AccountsEntryPoint.cs 
*
* AccountsEntryPoint.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.Design;

using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Plugins.Attributes;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Accounts.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Loading.Routing;
using VNLib.Plugins.Essentials.Accounts.SecurityProvider;

namespace VNLib.Plugins.Essentials.Accounts
{
    public sealed class AccountsEntryPoint : PluginBase
    {

        public override string PluginName => "Essentials.Accounts";

        private AccountSecProvider? _securityProvider;

        [ServiceConfigurator]
        public void ConfigureServices(IServiceContainer services)
        {
            //Export the build in security provider 
            if (_securityProvider != null)
            {
                services.AddService(typeof(IAccountSecurityProvider), _securityProvider);
                
                //Export as middleware
                services.AddService(typeof(IHttpMiddleware[]), new IHttpMiddleware[] { _securityProvider });
            }
        }

        protected override void OnLoad()
        {
            //Add optional endpoint routing

            if (this.HasConfigForType<LoginEndpoint>())
            {
                this.Route<LoginEndpoint>();
                this.Route<LogoutEndpoint>();
            }

            if (this.HasConfigForType<KeepAliveEndpoint>())
            {
                this.Route<KeepAliveEndpoint>();
            }

            if (this.HasConfigForType<ProfileEndpoint>())
            {
                this.Route<ProfileEndpoint>();
            }

            if (this.HasConfigForType<PasswordChangeEndpoint>())
            {
                this.Route<PasswordChangeEndpoint>();
            }           

            if (this.HasConfigForType<MFAEndpoint>())
            {
                this.Route<MFAEndpoint>();
            }

            if (this.HasConfigForType<PkiLoginEndpoint>())
            {
                this.Route<PkiLoginEndpoint>();
            }

            //Only export the account security service if the configuration element is defined
            if (this.HasConfigForType<AccountSecProvider>())
            {
                //Inint the security provider
                _securityProvider = this.GetOrCreateSingleton<AccountSecProvider>();

                Log.Information("Configuring the account security provider service");
            }

            //Write loaded to log
            Log.Information("Plugin loaded");
        }

     

        protected override void OnUnLoad()
        {
            //Write closing messsage and dispose the log
            Log.Information("Plugin unloaded");
        }
      
        protected override async void ProcessHostCommand(string cmd)
        {
            //Only process commands if the plugin is in debug mode
            if (!this.IsDebug())
            {
                return;
            }
            try
            {
                IUserManager Users = this.GetOrCreateSingleton<UserManager>();
                IPasswordHashingProvider Passwords = this.GetOrCreateSingleton<ManagedPasswordHashing>();

                //get args as a list
                List<string> args = cmd.Split(' ').ToList();
                if (args.Count < 3)
                {
                    Log.Warn("No command specified");
                }
                switch (args[2].ToLower())
                {
                    //Create new user
                    case "create":
                        {
                            int uid = args.IndexOf("-u");
                            int pwd = args.IndexOf("-p");
                            if (uid < 0 || pwd < 0)
                            {
                                Log.Warn("You are missing required argument values. Format 'create -u <username> -p <password>'");
                                return;
                            }
                            string username = args[uid + 1].Trim();
                            string randomUserId = AccountUtil.GetRandomUserId();
                            //Password as privatestring DANGEROUS to refs
                            using (PrivateString password = (PrivateString)args[pwd + 1].Trim()!)
                            {
                                //Hash the password
                                using PrivateString passHash = Passwords.Hash(password);
                                //Create the user
                                using IUser user = await Users.CreateUserAsync(randomUserId, username, AccountUtil.MINIMUM_LEVEL, passHash);                                
                                //Set active flag
                                user.Status = UserStatus.Active;
                                //Set local account
                                user.SetAccountOrigin(AccountUtil.LOCAL_ACCOUNT_ORIGIN);

                                await user.ReleaseAsync();
                            }
                            Log.Information("Successfully created user {id}", username);

                        }
                        break;
                    case "reset":
                        {
                            int uid = args.IndexOf("-u");
                            int pwd = args.IndexOf("-p");
                            if (uid < 0 || pwd < 0)
                            {
                                Log.Warn("You are missing required argument values. Format 'reset -u <username> -p <password>'");
                                return;
                            }
                            string username = args[uid + 1].Trim();
                            //Password as privatestring DANGEROUS to refs
                            using (PrivateString password = (PrivateString)args[pwd + 1].Trim()!)
                            {
                                //Hash the password
                                using PrivateString passHash = Passwords.Hash(password);
                                //Get the user
                                using IUser? user = await Users.GetUserFromEmailAsync(username);

                                if(user == null)
                                {
                                    Log.Warn("The specified user does not exist");
                                    break;
                                }
                                
                                //Set the password
                                await Users.UpdatePassAsync(user, passHash);
                            }
                            Log.Information("Successfully reset password for {id}", username);
                        }
                        break;
                    case "delete":
                        {
                            //get user-id
                            string userId = args[3].Trim();
                            //Get user
                            using IUser? user = await Users.GetUserFromEmailAsync(userId);
                            
                            if (user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }
                            
                            //delete user
                            user.Delete();
                            //Release user
                            await user.ReleaseAsync();
                        }
                        break;
                    default:
                        Log.Warn("Uknown command");
                        break;
                }
            }
            catch (UserExistsException)
            {
                Log.Error("User already exists");
            }
            catch(UserCreationFailedException)
            {
                Log.Error("Failed to create the new user");
            }
            catch (ArgumentOutOfRangeException)
            {
                Log.Error("You are missing required command arguments");
            }
            catch(Exception ex)
            {
                Log.Error(ex);    
            }
        }
    }
}