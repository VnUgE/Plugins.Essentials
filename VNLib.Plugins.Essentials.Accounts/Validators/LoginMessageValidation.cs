using System;

using FluentValidation;

using VNLib.Plugins.Extensions.Validation;

namespace VNLib.Plugins.Essentials.Accounts.Validators
{

    internal class LoginMessageValidation : AbstractValidator<LoginMessage>
    {
        public LoginMessageValidation()
        {
            RuleFor(static t => t.ClientID)
                .Length(min: 10, max: 100)
                .WithMessage(errorMessage: "Your browser is not sending required security information");

            RuleFor(static t => t.ClientPublicKey)
             .NotEmpty()
             .Length(min: 50, max: 1000)
             .WithMessage(errorMessage: "Your browser is not sending required security information");

            /* Rules for user-input on passwords, set max length to avoid DOS */
            RuleFor(static t => t.Password)
                .SetValidator(AccountValidations.PasswordValidator);
            
            //Username/email address
            RuleFor(static t => t.UserName)
                .Length(min: 1, max: 64)
                .WithName(overridePropertyName: "Email")
                .EmailAddress()
                .WithName(overridePropertyName: "Email")
                .IllegalCharacters()
                .WithName(overridePropertyName: "Email");               

            RuleFor(static t => t.LocalLanguage)
                .NotEmpty()
                .IllegalCharacters()
                .WithMessage(errorMessage: "Your language is not supported");   

            RuleFor(static t => t.LocalTime.ToUniversalTime())
                .Must(static time => time > DateTime.UtcNow.AddSeconds(-60) && time < DateTime.UtcNow.AddSeconds(60))
                .WithMessage(errorMessage: "Please check your system clock");
        }
    }
}
