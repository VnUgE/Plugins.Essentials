// Copyright (c) 2023 Vaughn Nugent
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

import { defaultTo, first } from "lodash-es";
import { get } from "@vueuse/core";
import { ref, type MaybeRef } from "vue";
import { useFormToaster } from "../toast";
import type { IErrorNotifier } from "../toast";

/**
 * Represents a validator that performs validation and returns a boolean
 * along with an error message if the validation fails
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

export interface ValidationWrapper {
    /**
     * Computes the validation of the wrapped validator and captures the results.
     * If the validation fails, the first error message is displayed in a toast notification.
     * @returns The result of the validation
     */
    validate: () => Promise<boolean>;
}

export interface VuelidateInstance {
    $validate: () => Promise<boolean>;
    $errors: Array<{ $message: string }>;
}

//Wrapper around a Vuelidate validator
const createVuelidateWrapper = <T extends VuelidateInstance>(validator: Readonly<MaybeRef<T>>): IValidator => {
    const validate = async (): Promise<boolean> => {
        return get(validator).$validate();
    }

    const firstError = (): Error => {
        const errs = get(validator).$errors;
        return new Error(first(errs)?.$message);
    }

    return { validate, firstError }
}

const createValidator = <T extends IValidator>(validator: MaybeRef<T>, toaster: IErrorNotifier): ValidationWrapper => {
    const validate = async (): Promise<boolean> => {
        // Validate the form
        const valid = await get(validator).validate();
        // If the form is no valid set the error message
        if (!valid) {
            const first = get(validator).firstError();
            // Set the error message to the first error in the form list
            toaster.notifyError(first.message);
        }
        return valid
    }

    return { validate }
}

/**
 * Wraps a validator with a toaster to display validation errors
 * @param validator The validator to wrap
 * @param toaster The toaster to use for validation errors
 * @returns The validation toast wrapper
 * @example returns { validate: Function<Promise<boolean>> }
 * const { validate } = useValidationWrapper(validator, toaster)
 * const result = await validate()
 */
export const useValidationWrapper = <T extends IValidator>(validator: Readonly<MaybeRef<T>>, toaster?: IErrorNotifier): ValidationWrapper => {
    return createValidator(validator, toaster ?? useFormToaster());
}

/**
 * Wraps a Vuelidate validator with a toaster to display validation errors
 * @param validator The vuelidate instance to wrap
 * @param toaster The toaster to use for validation errors
 * @returns The validation toast wrapper
 * @example returns { validate: Function<Promise<boolean>> }
 * const { validate } = useValidationWrapper(validator, toaster)
 * const result = await validate()
 */
export const useVuelidateWrapper = <T extends VuelidateInstance>(v$: Readonly<MaybeRef<T>>, toaster?: IErrorNotifier) => {
    const wrapper = createVuelidateWrapper(v$);
    //Vuelidate class wrapper around the validator
    const validator = ref(wrapper);
    return createValidator(validator, defaultTo(toaster, useFormToaster()));
}
