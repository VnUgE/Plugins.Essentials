﻿/*
* Copyright (c) 2025 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts
* File: LoginMessageValidation.cs 
*
* LoginMessageValidation.cs is part of VNLib.Plugins.Essentials.Accounts which is part of the larger 
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

using FluentValidation;

using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Accounts.Validators
{

    internal sealed class LoginMessageValidation : ClientSecurityMessageValidator<LoginMessage>
    {
        public LoginMessageValidation(bool enforceEmail, int maxUernameLen) : base()
        {

            /* Rules for user-input on passwords, set max length to avoid DOS */
            RuleFor(static t => t.Password)
                .SetValidator(AccountValidations.PasswordValidator);

            //Username/email address
            RuleFor(static t => t.UserName)
                .NotEmpty()
                .Length(min: 1, max: maxUernameLen)
                .IllegalCharacters()
                .EmailAddress()
                .When(_ => enforceEmail) //Only require email if enforced by configuration
                .WithName(overridePropertyName: "Email");

            RuleFor(static t => t.LocalLanguage!)
                .NotEmpty()
                .IllegalCharacters()
                .WithMessage(errorMessage: "Your language is not supported");

            RuleFor(static t => t.LocalTime.ToUniversalTime())
                .Must(static time => time > DateTime.UtcNow.AddSeconds(-60) && time < DateTime.UtcNow.AddSeconds(60))
                .WithMessage(errorMessage: "Please check your system clock")
                .WithName("localtime");
        }
    }
}
