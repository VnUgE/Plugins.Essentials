/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.SocialOauth
* File: AccountDataValidator.cs 
*
* AccountDataValidator.cs is part of VNLib.Plugins.Essentials.SocialOauth which is part of the larger 
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

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Validation;

#nullable enable

namespace VNLib.Plugins.Essentials.SocialOauth.Validators
{
    internal class AccountDataValidator : AbstractValidator<AccountData>
    {
        public AccountDataValidator() : base()
        {
            RuleFor(t => t.EmailAddress)
                .NotEmpty()
                .WithMessage("Your account does not have an email address assigned to it");

            RuleFor(t => t.EmailAddress)
                .EmailAddress()
                .WithMessage("Your account does not have a valid email address assigned to it");

            //Validate city
            RuleFor(t => t.City).MaximumLength(50);
            RuleFor(t => t.City).AlphaOnly();

            RuleFor(t => t.Company).MaximumLength(50);
            RuleFor(t => t.Company).SpecialCharacters();

            RuleFor(t => t.First).MaximumLength(35);
            RuleFor(t => t.First).AlphaOnly();

            RuleFor(t => t.Last).MaximumLength(35);
            RuleFor(t => t.Last).AlphaOnly();

            RuleFor(t => t.PhoneNumber)
                .EmptyPhoneNumber()
                .OverridePropertyName("Phone");

            //State must be 2 characters for us states if set
            RuleFor(t => t.State).Length(t => t.State?.Length != 0 ? 2 : 0);

            RuleFor(t => t.Street).MaximumLength(50);
            RuleFor(t => t.Street).AlphaNumericOnly();

            RuleFor(t => t.Zip).NumericOnly();
            //Allow empty zip codes, but if one is defined, is must be less than 7 characters
            RuleFor(t => t.Zip).Length(ad => ad.Zip?.Length != 0 ? 7 : 0);
        }
    }
}
