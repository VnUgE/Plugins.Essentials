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

import { type Ref, readonly, ref } from '@vue/reactivity';
import { defaultTo, isArray, isNil, first, isString } from 'lodash-es';
import type { Toaster } from './toaster';

export interface UseApiCallArgs {
    readonly toaster: Toaster
}

export interface UseApiCallReturn {
    /**
     * The api call function object {apiCall: Promise }
     */
    <TR>(callback: () => Promise<TR | undefined>): Promise<TR | undefined>;
    /**
     * The api call function object {apiCall: Promise }
     */
    invoke<TR>(callback: () => Promise<TR | undefined>): Promise<TR | undefined>;
    /**
     * The waiting flag that indicates if the api call is in progress
     */
    readonly waiting: Readonly<Ref<boolean>>;
}

// Defined by the vnlib client-server api
type ValidationError = { property: string, message: string } 
type ErrorResponse = ValidationError | string

/**
 * Provides a wrapper method for making remote api calls to a server
 * while capturing context and errors and common api arguments.
 * @param args - 
 * @returns API call wrapper with waiting state
 */
export const useApiCall = ({ toaster }: UseApiCallArgs): UseApiCallReturn => {
    
    const waitValue = ref(false);

    const setWaiting = (value: boolean) => waitValue.value = value; 

    const invoke = async <TR>(callback: () => Promise<TR | undefined>)
        : Promise<TR | undefined> => {

        // Set the waiting flag
        setWaiting(true);

        try {
            //Close previous toasts
            toaster.close();

            //Execute the async function
            return await callback();

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (errMsg: any) {
            console.error(errMsg)

            // See if the error has an axios response
            if (isNil(errMsg.response)) {
                if (errMsg.message === 'Network Error') {
                    toaster.error('Network Error', 'Please check your internet connection');
                } else {
                    toaster.error('An unknown error occurred');
                }
                return;
            }

            // Axios error message
            const response = errMsg.response
            const errors = response?.data?.errors as ErrorResponse[]
            const hasErrors = isArray(errors) && errors.length > 0

            const showErrorMessage = (defaultMessage: string) => {
                if (hasErrors) {
                    const firstError = first(errors);

                    if (isString(firstError)) {
                        toaster.error(firstError);
                    } 
                    else {
                        const { message, property } = firstError as ValidationError;
                        toaster.error( `Please verify your ${property ?? 'form'}`, message);
                    }
                } else {
                    const serverMessage = defaultTo(response?.data?.result, defaultMessage);
                    toaster.error(serverMessage);
                }
            };

            switch (response.status) {
                case 200:
                    break;
                case 400:
                    showErrorMessage('Bad Request');
                    break;
                case 422:
                    showErrorMessage('The server did not accept the request');
                    break;
                case 401:
                    showErrorMessage('You are not logged in');
                    break;
                case 403:
                    showErrorMessage('Please clear your cookies/cache and try again');
                    break;
                case 404:
                    showErrorMessage('The requested resource was not found');
                    break;
                case 409:
                    showErrorMessage('Please clear your cookies/cache and try again');
                    break;
                case 410:
                    showErrorMessage('The requested resource has expired');
                    break;
                case 423:
                    showErrorMessage('The requested resource is locked');
                    break;
                case 429:
                    showErrorMessage('You have made too many requests, please try again later');
                    break;
                case 500:
                    showErrorMessage('There was an error processing your request');
                    break;
                default:
                    showErrorMessage('An unknown error occurred');
                    break;
            }
        } finally {
            // Clear the waiting flag
            setWaiting(false);
        }
    }

    //Confiugre the api call to use global configuration
    const apiCall = Object.assign(invoke, {
        waiting: readonly(waitValue),
        invoke
    });
    
    return apiCall;
}
