using System;
using System.ComponentModel.DataAnnotations;

namespace VNLib.Plugins.Essentials.Accounts.Registration.TokenRevocation
{

    internal class RevokedToken
    {
        /// <summary>
        /// The time the token was revoked.
        /// </summary>
        public DateTime Created { get; set; }
        /// <summary>
        /// The token that was revoked.
        /// </summary>
        [Key]
        public string? Token { get; set; }
    }
}