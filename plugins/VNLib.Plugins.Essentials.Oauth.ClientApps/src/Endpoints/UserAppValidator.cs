/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Oauth.ClientApps
* File: UserAppValidator.cs 
*
* UserAppValidator.cs is part of VNLib.Plugins.Essentials.Oauth.ClientApps which 
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

using FluentValidation;
using FluentValidation.Results;

using VNLib.Plugins.Extensions.Validation;
using VNLib.Plugins.Essentials.Oauth.Applications;

namespace VNLib.Plugins.Essentials.Oauth.ClientApps.Endpoints
{
    internal class UserAppValidator : AbstractValidator<UserApplication>
    {
        public UserAppValidator()
        {
            //Name rules
            RuleFor(p => p.AppName)
                .Length(1, 50)
                .WithName("App name")
                .SpecialCharacters()
                .WithName("App name");
            //Description rules
            RuleFor(app => app.AppDescription)
                .SpecialCharacters()
                .WithName("Description")
                .MaximumLength(100)
                .WithName("Description");
            RuleFor(app => app.Permissions)
                .MaximumLength(100)
                .SpecialCharacters()
                .WithMessage("Invalid permissions");
        }

        public override ValidationResult Validate(ValidationContext<UserApplication> context)
        {
            //Get a ref to the app
            UserApplication app = context.InstanceToValidate;
            //remove unused fields
            app.ClientId = null;
            app.SecretHash = null;
            //validate the rest of the app
            return base.Validate(context);
        }
    }

}