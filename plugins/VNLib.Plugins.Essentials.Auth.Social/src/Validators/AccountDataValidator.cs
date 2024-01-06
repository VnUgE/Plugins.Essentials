/*
* Copyright (c) 2024 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Auth.Social
* File: AccountDataValidator.cs 
*
* AccountDataValidator.cs is part of VNLib.Plugins.Essentials.Auth.Social which is part of the larger 
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

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts;
using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Auth.Social.Validators
{
    internal class AccountDataValidator : AbstractValidator<AccountData>
    {
        public AccountDataValidator() : base()
        {
            RuleFor(t => t.EmailAddress)
                .NotEmpty()
                .WithMessage("Your account does not have an email address assigned to it");

            RuleFor(t => t.City)
                .MaximumLength(35)
                .AlphaOnly()
                .When(t => t.City?.Length > 0);

            RuleFor(t => t.Company)
                .MaximumLength(50)
                .SpecialCharacters()
                .When(t => t.Company?.Length > 0);

            //Require a first and last names to be set together
            When(t => t.First?.Length > 0 || t.Last?.Length > 0, () =>
            {
                RuleFor(t => t.First)
                    .Length(1, 35)
                    .AlphaOnly();
                RuleFor(t => t.Last)
                    .Length(1, 35)
                    .AlphaOnly();
            });

            RuleFor(t => t.PhoneNumber)
                .PhoneNumber()
                .When(t => t.PhoneNumber?.Length > 0)
                .OverridePropertyName("Phone");

            //State must be 2 characters for us states if set
            RuleFor(t => t.State)
                .Length(2)
                .When(t => t.State?.Length > 0);

            RuleFor(t => t.Street)
                .AlphaNumericOnly()
                .MaximumLength(50)
                .When(t => t.Street?.Length > 0);

            //Allow empty zip codes, but if one is defined, is must be less than 7 characters
            RuleFor(t => t.Zip)
                .NumericOnly()
                .MaximumLength(7)
                .When(t => t.Zip?.Length > 0);
        }
    }
}
