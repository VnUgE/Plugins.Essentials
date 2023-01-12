/*
* Copyright (c) 2022 Vaughn Nugent
* 
* Library: VNLib
* Package: VNLib.Plugins.Essentials.Accounts.Registration
* File: AccountValidations.cs 
*
* AccountValidations.cs is part of VNLib.Plugins.Essentials.Accounts.Registration which is part of the larger 
* VNLib collection of libraries and utilities.
*
* VNLib.Plugins.Essentials.Accounts.Registration is free software: you can redistribute it and/or modify 
* it under the terms of the GNU Affero General Public License as 
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* VNLib.Plugins.Essentials.Accounts.Registration is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see https://www.gnu.org/licenses/.
*/

using FluentValidation;

using VNLib.Plugins.Essentials.Accounts.Registration.Endpoints;
using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Accounts.Registration
{
    internal static class AccountValidations
    {
        /// <summary>
        /// Central password requirement validator
        /// </summary>
        public static IValidator<string> PasswordValidator { get; } = GetPassVal();

        public static IValidator<AccountData> AccountDataValidator { get; } = GetAcVal();

        /// <summary>
        /// A validator used to validate new registration request messages
        /// </summary>
        public static IValidator<RegRequestMessage> RegRequestValidator { get; } = GetRequestValidator();

        static IValidator<string> GetPassVal()
        {
            InlineValidator<string> passVal = new();

            passVal.RuleFor(static password => password)
                .NotEmpty()
                .Length(min: 8, max: 100)
                .Password()
                .WithMessage(errorMessage: "Password does not meet minium requirements");

            return passVal;
        }

        static IValidator<AccountData> GetAcVal()
        {
            InlineValidator<AccountData> adv = new ();

            //Validate city

            adv.RuleFor(t => t.City)
                .MaximumLength(35)
                .AlphaOnly()
                .When(t => t.City?.Length > 0);

            adv.RuleFor(t => t.Company)
                .MaximumLength(50)
                .SpecialCharacters()
                .When(t => t.Company?.Length > 0);

            //Require a first and last names to be set together
            adv.When(t => t.First?.Length > 0 || t.Last?.Length > 0, () =>
            {
                adv.RuleFor(t => t.First)
                    .Length(1, 35)
                    .AlphaOnly();
                adv.RuleFor(t => t.Last)
                    .Length(1, 35)
                    .AlphaOnly();
            });

            adv.RuleFor(t => t.PhoneNumber)
                .PhoneNumber()
                .When(t => t.PhoneNumber?.Length > 0)
                .OverridePropertyName("Phone");

            //State must be 2 characters for us states if set
            adv.RuleFor(t => t.State)
                .Length(2)
                .When(t => t.State?.Length > 0);

            adv.RuleFor(t => t.Street)
                .AlphaNumericOnly()
                .MaximumLength(50)
                .When(t => t.Street?.Length > 0);

            //Allow empty zip codes, but if one is defined, is must be less than 7 characters
            adv.RuleFor(t => t.Zip)
                .NumericOnly()
                .MaximumLength(7)
                .When(t => t.Zip?.Length > 0);

            return adv;
        }

        static IValidator<RegRequestMessage> GetRequestValidator()
        {
            InlineValidator<RegRequestMessage> reqVal = new();

            reqVal.RuleFor(static s => s.ClientId)
                .NotEmpty()
                .AlphaNumericOnly()
                .Length(1, 100);

            //Convert to universal time before validating
            reqVal.RuleFor(static s => s.Timestamp.ToUniversalTime())
                .Must(t => t > DateTimeOffset.UtcNow.AddSeconds(-60) && t < DateTimeOffset.UtcNow.AddSeconds(60));

            reqVal.RuleFor(static s => s.UserName)
                .NotEmpty()
                .EmailAddress()
                .IllegalCharacters()
                .Length(5, 50);

            return reqVal;
        }
    }
}
