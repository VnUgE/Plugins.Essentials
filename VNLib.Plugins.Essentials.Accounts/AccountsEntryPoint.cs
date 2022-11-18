using System;
using System.Linq;
using System.Collections.Generic;

using VNLib.Utils.Memory;
using VNLib.Utils.Logging;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Accounts.Endpoints;
using VNLib.Plugins.Extensions.Loading;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Extensions.Loading.Routing;

namespace VNLib.Plugins.Essentials.Accounts
{
    public sealed class AccountsEntryPoint : PluginBase
    {

        public override string PluginName => "Essentials.Accounts";

        protected override void OnLoad()
        {
            try
            {
                //Route endpoints
                this.Route<LoginEndpoint>();

                this.Route<LogoutEndpoint>();

                this.Route<KeepAliveEndpoint>();

                this.Route<ProfileEndpoint>();

                this.Route<PasswordChangeEndpoint>();

                this.Route<MFAEndpoint>();

                //Write loaded to log
                Log.Information("Plugin loaded");
            }
            catch (KeyNotFoundException knf)
            {
                Log.Error("Missing required account configuration variables {mess}", knf.Message);
            }
            catch (UriFormatException uri)
            {
                Log.Error("Invalid endpoint URI {message}", uri.Message);
            }
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
                IUserManager Users = this.GetUserManager();
                PasswordHashing Passwords = this.GetPasswords();

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
                            string randomUserId = AccountManager.GetRandomUserId();
                            //Password as privatestring DANGEROUS to refs
                            using (PrivateString password = (PrivateString)args[pwd + 1].Trim()!)
                            {
                                //Hash the password
                                using PrivateString passHash = Passwords.Hash(password);
                                //Create the user
                                using IUser user = await Users.CreateUserAsync(randomUserId, username, AccountManager.MINIMUM_LEVEL, passHash);                                
                                //Set active flag
                                user.Status = UserStatus.Active;
                                //Set local account
                                user.SetAccountOrigin(AccountManager.LOCAL_ACCOUNT_ORIGIN);

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