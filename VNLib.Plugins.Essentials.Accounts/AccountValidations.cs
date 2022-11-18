﻿
using FluentValidation;

using VNLib.Plugins.Extensions.Validation;

#nullable enable

namespace VNLib.Plugins.Essentials.Accounts
{
    public static class AccountValidations
    {
        /// <summary>
        /// Central password requirement validator
        /// </summary>
        public static IValidator<string> PasswordValidator { get; } = GetPassVal();

        public static IValidator<AccountData> AccountDataValidator { get; } = GetAcVal();
     

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
    }
}
