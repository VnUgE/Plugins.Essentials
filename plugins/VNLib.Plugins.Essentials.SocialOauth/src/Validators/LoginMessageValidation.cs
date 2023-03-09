/*
* Copyright (c) 2023 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: LoginMessageValidation.cs 
*
* LoginMessageValidation.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.SocialOauth is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.SocialOauth is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using System;

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.SocialOauth.Validators
{
    internal class LoginMessageValidation : AbstractValidator<LoginMessage>
    {
        /*
         * A login message object is only used for common semantics within
         *  the user-system so validation operations are different than a
         *  normal login endpoint as named fields may be used differently
         */
        public LoginMessageValidation()
        {
            RuleFor(t => t.ClientId)
                .Length(10, 50)
                .WithMessage("Your browser is not sending required security information")
                .IllegalCharacters()
                .WithMessage("Your browser is not sending required security information");

            RuleFor(t => t.ClientPublicKey)
             .Length (50, 1000)
             .WithMessage("Your browser is not sending required security information")
             .IllegalCharacters()
             .WithMessage("Your browser is not sending required security information");

            //Password is only used for nonce tokens
            RuleFor(t => t.Password).NotEmpty();

            RuleFor(t => t.LocalLanguage)
                .NotEmpty()
                .WithMessage("Your language is not supported")
                .AlphaNumericOnly()
                .WithMessage("Your language is not supported");
        }
    }
}
