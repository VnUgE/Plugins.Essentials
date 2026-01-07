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
import type { MaybeRef } from '@vue/reactivity'
import { get } from '@vueuse/core';
import { type Toaster } from "./toaster";

/**
 * Represents a generic validator interface that can be used for form validation.
 */
export interface IValidator {
    /**
     * Performs asynchronous validation and returns a boolean indicating success.
     * @returns Promise resolving to true if validation passes
     */
    validate(): Promise<boolean>;
    /**
     * Returns the first error message in the validation list.
     * @returns Error object with the first validation failure message
     */
    firstError(): Error;
}

/**
 * Represents a Vuelidate validator instance with validation methods and error tracking.
 */
export interface VuelidateInstance {
    /**
     * Computes validation and captures results.
     * @returns Promise resolving to true if all validations pass
     */
     $validate: () => Promise<boolean>;
    /** Array of validation error messages */
    $errors: Array<{ $message: MaybeRef<string> }>;
}

/**
 * Function signature for validating forms with optional toast notifications.
 */
export interface ValidateFunction {
    (validator: MaybeRef<VuelidateInstance>, toaster?: Toaster): Promise<boolean>;
    (validator: MaybeRef<IValidator>, toaster?: Toaster): Promise<boolean>;
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

/**
 * Union type accepting either Vuelidate or custom validator instances.
 */
export type VuelidateOrValidator = VuelidateInstance | IValidator;

/**
 * Validates a form using the provided validator and displays an error message
 * if the validation fails.
 * @template T - Validator type extending VuelidateInstance
 * @param toaster - Toaster instance to display error messages
 * @param validator - The validator to use for validation (Vuelidate or IValidator)
 * @returns Promise resolving to true if validation succeeds, false otherwise
 */
export const validateForm = async <T extends VuelidateInstance>(toaster: Toaster, validator: MaybeRef<T>)
   : Promise<boolean> => {

    const instance = wrapVuelidate(validator);

    // Validate the form
    const valid = await instance.validate();

    // If the form is no valid set the error message
    if (!valid) {
        const first = instance.firstError();
        // Set the error message to the first error in the form list
        toaster?.error(first.message);
    }

    return valid;
}
