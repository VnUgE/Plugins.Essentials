using System;
using System.Linq;
using System.Net;
using System.Text.Json;

using VNLib.Utils;
using VNLib.Plugins.Essentials.Users;
using VNLib.Plugins.Essentials.Extensions;
using VNLib.Plugins.Essentials.Accounts.Admin.Model;
using VNLib.Plugins.Extensions.Data;
using VNLib.Plugins.Extensions.Loading.Sql;
using VNLib.Plugins.Extensions.Loading.Users;
using VNLib.Plugins.Essentials.Accounts.Admin.Helpers;
using VNLib.Plugins.Extensions.Loading;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Endpoints
{
    [ConfigurationName("users")]
    internal class UsersEndpoint : LocalNetworkProtectedEndpoint
    {

        readonly IUserManager Manager;
        readonly UserStore UserStore;

        public UsersEndpoint(PluginBase plugin, Dictionary<string, JsonElement> config)
        {
            this.LocalOnly = plugin.LocalOnlyEnabled();
            string? path = config["path"].GetString();
            //Store user-manager
            Manager = plugin.GetUserManager();
            //Create the indirect user context store
            UserStore = new(plugin.GetContextOptions());
            
            InitPathAndLog(path, plugin.Log);
        }


        protected override ERRNO PreProccess(HttpEntity entity)
        {
            return base.PreProccess(entity) && entity.Session.IsAdmin();
        }

        protected override async ValueTask<VfReturnType> GetAsync(HttpEntity entity)
        {                
            //Get single account
            if(entity.QueryArgs.TryGetNonEmptyValue("id", out string? userId))
            {
                //Load account
                using IUser? user = await Manager.GetUserFromIDAsync(userId);
                AccountData? acc = user?.GetProfile();
                //If account not found, return 404
                if(acc == null)
                {
                    entity.CloseResponse(HttpStatusCode.NotFound);
                }
                else
                {
                    entity.CloseResponseJson(HttpStatusCode.OK, acc);
                }
            }
            else
            {
                //Get a user page
                int page = entity.QueryArgs.GetPageOrDefault(0);
                int limit = entity.QueryArgs.GetLimitOrDefault(50, 0, 200);
                //Rent list and get the requested page
                List<User> rental = UserStore.ListRental.Rent();
                _ = await UserStore.GetPageAsync(rental, page, limit);
                //Set response
                entity.CloseResponseJson(HttpStatusCode.OK, rental);
                //Return list to store
                UserStore.ListRental.Return(rental);
            }           
            return VfReturnType.VirtualSkip;
        }
    }
}
