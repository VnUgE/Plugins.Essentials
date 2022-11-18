using System;

using VNLib.Utils;
using VNLib.Plugins.Essentials.Endpoints;

namespace VNLib.Plugins.Essentials.Accounts.Admin.Helpers
{
    /// <summary>
    /// Provides an endpoint that provides optional protection against requests outside the local network
    /// </summary>
    internal abstract class LocalNetworkProtectedEndpoint : ProtectedWebEndpoint
    {
        private bool _localOnly;

        /// <summary>
        /// Specifies if requests outside of the local network are allowed.
        /// </summary>
        protected bool LocalOnly
        {
            get => _localOnly;
            set => _localOnly = value;
        }

        protected override ERRNO PreProccess(HttpEntity entity)
        {
            return (!_localOnly || entity.IsLocalConnection) && base.PreProccess(entity);
        }

    }
}
