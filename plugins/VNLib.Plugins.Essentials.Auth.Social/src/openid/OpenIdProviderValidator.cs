/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: OauthClientConfig.cs 
*
* OauthClientConfig.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Auth.Social is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Auth.Social is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;

using FluentValidation;

namespace VNLib.Plugins.Essentials.Auth.Social.openid
{
    public sealed class OpenIdProviderValidator : AbstractValidator<OpenIdPortalConfig>
    {
        public OpenIdProviderValidator(string discoveryUrl)
        {
            /*
             * Discovery url will be compared to make sure the 
             * host is on the same domain as the issuer
             */
            Uri discUrl = new(discoveryUrl);

            RuleFor(i => i.IssuerUrl)
                .Matches($"^{discUrl.Scheme}://{discUrl.Host}")
                .WithMessage("Issuer must be on the same domain as the discovery url");

            RuleFor(i => i.AuthorizationEndpoint)
                .NotEmpty()
                .WithMessage("Authorization endpoint is required")
                .Matches($"^{discUrl.Scheme}://{discUrl.Host}")
                .WithMessage("Authorization endpoint must be on the same domain as the discovery url");

            RuleFor(i => i.TokenEndpoint)
                .NotEmpty()
                .WithMessage("Token endpoint is required")
                .Matches($"^{discUrl.Scheme}://{discUrl.Host}")
                .WithMessage("Token endpoint must be on the same domain as the discovery url");

            RuleFor(i => i.UserDataEndpoint)
                .NotEmpty()
                .WithMessage("User data endpoint is required")
                .Matches($"^{discUrl.Scheme}://{discUrl.Host}")
                .WithMessage("User data endpoint must be on the same domain as the discovery url");

            RuleFor(i => i.KeysEndpoint)
                .NotEmpty()
                .WithMessage("Keys endpoint is required")
                .Matches($"^{discUrl.Scheme}://{discUrl.Host}")
                .WithMessage("Keys endpoint must be on the same domain as the discovery url");
        }
    }
}
