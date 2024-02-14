/*
* Copyright (c) 2024 Vaughn Nugent
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
using System.Text.Json;

using FluentValidation.Results;

using VNLib.Utils;
using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Middleware;
using VNLib.Plugins.Essentials.Accounts.MFA;
using VNLib.Plugins.Essentials.Accounts.Endpoints;
using VNLib.Plugins.Essentials.Accounts.SecurityProvider;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Loading.Routing;

namespace VNLib.Plugins.Essentials.Accounts
{

    public sealed class AccountsEntryPoint : PluginBase
    {

        public override string PluginName => "Essentials.Accounts";

        private bool SetupMode => HostArgs.HasArgument("--account-setup");

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
                //Inint the security provider and export it
                AccountSecProvider securityProvider = this.GetOrCreateSingleton<AccountSecProvider>();
                this.ExportService<IAccountSecurityProvider>(securityProvider);

                //Also add the middleware array
                this.ExportService(new IHttpMiddleware[] { securityProvider });

                Log.Information("Configuring the account security provider service");
            }

            if (SetupMode)
            {
                Log.Warn("Setup mode is enabled, this is not recommended for production use");
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
            //Only process commands if the plugin is in setup mode
            if (!SetupMode)
            {
                return;
            }
            try
            {
                //Create argument parser
                ArgumentList args = new(cmd.Split(' '));

                IUserManager Users = this.GetOrCreateSingleton<UserManager>();

                string? username = args.GetArgument("-u");
                string? password = args.GetArgument("-p");

                if (args.Count < 3)
                {
                    Log.Warn("Not enough arguments, use the help command to view available commands");
                    return;
                }

                switch (args[2].ToLower(null))
                {
                    case "help":
                        const string help = @"
    
Command help for {name}

Usage: p {name} <command> [options]

Commands:
    create -u <username> -p <password>                              Create a new user
    reset-password -u <username> -p <password> -l <priv level>      Reset a user's password
    delete -u <username>                                            Delete a user
    disable-mfa -u <username>                                       Disable a user's MFA configuration
    enable-totp -u <username> -s <base32 secret>                    Enable TOTP MFA for a user
    set-privilege -u <username> -l <priv level>                     Set a user's privilege level
    add-pubkey -u <username>                                        Add a JWK public key to a user's profile
    help                                                            Display this help message
";
                        Log.Information(help, PluginName);
                        break;
                    //Create new user
                    case "create":  
                        {
                            if (username == null || password == null)
                            {
                                Log.Warn("You are missing required argument values. Format 'create -u <username> -p <password>'");
                                break;
                            }

                            string? privilege = args.GetArgument("-l");

                            if(!ulong.TryParse(privilege, out ulong privLevel))
                            {
                                privLevel = AccountUtil.MINIMUM_LEVEL;
                            }

                            //Create the user creation request
                            UserCreationRequest creation = new()
                            {
                                EmailAddress = username,
                                InitialStatus = UserStatus.Active,
                                Privileges = privLevel,
                                Password = PrivateString.ToPrivateString(password, false)
                            };

                            //Create the user
                            using IUser user = await Users.CreateUserAsync(creation, null); 
                           
                            //Set local account
                            user.SetAccountOrigin(AccountUtil.LOCAL_ACCOUNT_ORIGIN);

                            await user.ReleaseAsync();

                            Log.Information("Successfully created user {id}", username);
                        }
                        break;
                    case "reset-password":
                        {
                            if (username == null || password == null)
                            {
                                Log.Warn("You are missing required argument values. Format 'create -u <username> -p <password>'");
                                break;
                            }

                            //Get the user
                            using IUser? user = await Users.GetUserFromUsernameAsync(username);

                            if(user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }
                                
                            //Set the password
                            await Users.UpdatePasswordAsync(user, password);
                            
                            Log.Information("Successfully reset password for {id}", username);
                        }
                        break;
                    case "delete":
                        {
                            if(username == null)
                            {
                                Log.Warn("You are missing required argument values. Format 'delete -u <username>'");
                                break;
                            }

                            //Get user
                            using IUser? user = await Users.GetUserFromUsernameAsync(username);
                            
                            if (user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }
                            
                            //delete user
                            user.Delete();
                            //Release user
                            await user.ReleaseAsync();

                            Log.Information("Successfully deleted user {id}", username);
                        }
                        break;
                    case "disable-mfa":
                        {
                            if (username == null)
                            {
                                Log.Warn("You are missing required argument values. Format 'disable-mfa -u <username>'");
                                break;
                            }

                            //Get user
                            using IUser? user = await Users.GetUserFromUsernameAsync(username);

                            if (user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }

                            user.MFADisable();
                            await user.ReleaseAsync();

                            Log.Information("Successfully disabled MFA for {id}", username);
                        }
                        break;
                    case "enable-totp":
                        {
                            string? secret = args.GetArgument("-s");

                            if (username == null || secret == null)
                            {
                                Log.Warn("You are missing required argument values. Format 'enable-totp -u <username> -s <secret>'");
                                break;
                            }

                            //Get user
                            using IUser? user = await Users.GetUserFromUsernameAsync(username);

                            if (user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }

                            try
                            {
                                byte[] sec = VnEncoding.FromBase32String(secret) ?? throw new Exception("");
                            }
                            catch
                            {
                                Log.Error("Your TOTP secret is not valid base32");
                                break;
                            }

                            //Update the totp secret and flush changes
                            user.MFASetTOTPSecret(secret);
                            await user.ReleaseAsync();

                            Log.Information("Successfully set TOTP secret for {id}", username);
                        }
                        break;
                    case "add-pubkey":
                        {

                            if (string.IsNullOrWhiteSpace(username))
                            {
                                Log.Warn("You are missing required argument values. Format 'add-pubkey -u <username>");
                                break;
                            }

                            Console.WriteLine("Enter public key JWK...");

                            //Wait for pubkey
                            string? pubkeyJwk = Console.ReadLine();

                            if(string.IsNullOrWhiteSpace(pubkeyJwk))
                            {
                                Log.Warn("No public key supplied.");
                                break;
                            }

                            //Get user
                            using IUser? user = await Users.GetUserFromUsernameAsync(username);

                            if (user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }

                            PkiAuthPublicKey? pubkey = JsonSerializer.Deserialize<PkiAuthPublicKey>(pubkeyJwk);
                            if (pubkey == null)
                            {
                                Log.Error("You public key is not a JSON object");
                                break;
                            }

                            //Validate
                            ValidationResult res = PkiLoginEndpoint.UserJwkValidator.Validate(pubkey);
                            if (!res.IsValid)
                            {
                                Log.Error("The public key JWK is not valid:\n{errors}", res.ToDictionary());
                                break;
                            }


                            //Add/update the public key and flush changes
                            user.PKIAddPublicKey(pubkey);
                            await user.ReleaseAsync();

                            Log.Information("Successfully set TOTP secret for {id}", username);
                        }
                        break;
                    case "set-privilege":
                        {
                            if (username == null)
                            {
                                Log.Warn("You are missing required argument values. Format 'set-privilege -u <username> -l <privilege level>'");
                                break;
                            }

                            string? privilege = args.GetArgument("-l");
                            if (!ulong.TryParse(privilege, out ulong privLevel))
                            {
                                Log.Warn("You are missing required argument values. Format 'set-privilege -u <username> -l <privilege level>'");
                                break;
                            }

                            //Get user
                            using IUser? user = await Users.GetUserFromUsernameAsync(username);
                            if (user == null)
                            {
                                Log.Warn("The specified user does not exist");
                                break;
                            }

                            user.Privileges = privLevel;
                            await user.ReleaseAsync();
                            Log.Information("Successfully set privilege level for {id}", username);
                        }
                        break;
                    default:
                        Log.Warn("Uknown command, use the help command");
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