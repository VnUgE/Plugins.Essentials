// Copyright (c) 2025 Vaughn Nugent
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import { first } from "lodash-es";
import { type MaybeRef, get } from '@vueuse/core';
import { useFormToaster, type IErrorNotifier } from "./toast";

/**
 * Represents a generic validator interface that can be used
 * for form validation.
 */
export interface IValidator {
    /**
     * Performs asynchronous validation and returns a boolean
     * indicating if the validation was successful
     */
    validate(): Promise<boolean>;
    /**
     * Returns the first error message in the validation list
     */
    firstError(): Error;
}

/**
 * Represents a validator that performs validation and returns a boolean
 * along with an error message if the validation fails
 */
export interface VuelidateInstance {
     /**
     * Computes the validation of the wrapped validator and captures the results.
     * If the validation fails, the first error message is displayed in a toast notification.
     * @returns The result of the validation
     */
    $validate: () => Promise<boolean>;
    $errors: Array<{ $message: MaybeRef<string> }>;
}

export interface ValidateFunction {
    (validator: MaybeRef<VuelidateInstance>, toaster?: IErrorNotifier): Promise<boolean>;
    (validator: MaybeRef<IValidator>, toaster?: IErrorNotifier): Promise<boolean>;
}

const wrapVuelidate = (validator: MaybeRef<VuelidateInstance | IValidator>): IValidator => {
    return {
        validate: async () => {
            const val = get(validator);

            if(val || '$validate' in val) {
                return (val as VuelidateInstance).$validate();
            }

            if (val || 'validate' in val) {
                return (val as IValidator).validate();
            }

            throw new Error('Validator is not a valid VuelidateInstance or IValidator');
        },
        firstError: () => {
            const val = get(validator);

            if (val || '$errors' in val) {
                const errs = (val as VuelidateInstance).$errors;
                return new Error(get(first(errs)?.$message || 'No error message found'));
            }

            if (val || 'firstError' in val) {
                return (val as IValidator).firstError();
            }

            throw new Error('Validator is not a valid VuelidateInstance or IValidator');
        }
    };
}

//Define any type that has a $validate method and an $errors property
export type VuelidateOrValidator = VuelidateInstance | IValidator;

/**
 * Validates a form using the provided validator and displays an error message
 * if the validation fails.
 * @param validator The validator to use for validation, can be a VuelidateInstance or IValidator
 * @param toaster Optional error notifier to display error messages
 * @returns A promise that resolves to true if the validation is successful, false otherwise
 */
export const validateForm = async <T extends VuelidateInstance>(validator: MaybeRef<T>, toaster?: IErrorNotifier)
   : Promise<boolean> => {

    const instance = wrapVuelidate(validator);
    toaster = toaster || useFormToaster();

    // Validate the form
    const valid = await instance.validate();
    // If the form is no valid set the error message
    if (!valid) {
        const first = instance.firstError();
        // Set the error message to the first error in the form list
        toaster?.notifyError(first.message);
    }

    return valid;
}
