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

import { type MaybeRefOrGetter, type Ref, readonly, ref } from '@vue/reactivity';
import { type AxiosRequestConfig, type Axios } from 'axios';
import { defaultTo, isArray, isNil, first, isString } from 'lodash-es';
import { get } from './reactivity';
import { useFormToaster, useToaster } from '../toast';
import { useAxios } from '../axios';
import type { IErrorNotifier, CombinedToaster } from '../toast';

export interface IApiHandle<T> {
    /**
     * Called to get the object to pass to apiCall is invoked
     */
    getCallbackObject(): T;

    /**
     * Called to get the notifier to use for the api call
     */
    getNotifier(): IErrorNotifier;

    /**
     * Called to set the waiting flag
     */
    setWaiting: (waiting: boolean) => void;
}

export interface IApiPassThrough {
    readonly axios: Axios;
    readonly toaster: CombinedToaster;
}

export interface UseApiCallReturn {
    /**
     * The api call function object {apiCall: Promise }
     */
    <TR>(callback: (data: IApiPassThrough) => Promise<TR | undefined>): Promise<TR | undefined>;
    /**
     * The api call function object {apiCall: Promise }
     */
    invoke<TR>(callback: (data: IApiPassThrough) => Promise<TR | undefined>): Promise<TR | undefined>;
    /**
     * The waiting flag that indicates if the api call is in progress
     */
    readonly waiting: Readonly<Ref<boolean>>;
}

export interface UseApiCallArgs {
    /**
     * The notifier to write errors to 
     */
    readonly notifier?: MaybeRefOrGetter<IErrorNotifier>;
    /**
     * The axios request configuration to use for the api call
     * If not provided, the default axios instance will be used
     */
    readonly axConfig?: AxiosRequestConfig | undefined | null;
}

export interface UseApiCall {
    (): UseApiCallReturn;
    (args: UseApiCallArgs): UseApiCallReturn;
}

// Defined by the vnlib client-server api
type ValidationError = { property: string, message: string } 
type ErrorResponse = ValidationError | string


/**
 * Provides a wrapper method for making remote api calls to a server
 * while capturing context and errors and common api arguments.
 * @returns {Object} The api call function object {apiCall: Promise }
 */
export const useApiCall: UseApiCall = (args?: UseApiCallArgs): UseApiCallReturn => {

    const { notifier, axConfig } = args ?? { notifier: useFormToaster() };

    const axios = useAxios(axConfig);
    const toaster = useToaster();
    const waitValue = ref(false);

    const getCallbackObject = (): IApiPassThrough => ({ axios, toaster })
    const setWaiting = (value: boolean) => waitValue.value = value;

    const invoke = async <TR>(callback: (data: IApiPassThrough) => Promise<TR | undefined>)
        : Promise<TR | undefined> => {
        const ntf = get(notifier)

        // Set the waiting flag
        setWaiting(true);

        try {
            //Close the current toast value
            ntf?.close();

            const obj = getCallbackObject();

            //Exec the async function
            return await callback(obj);

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (errMsg: any) {
            console.error(errMsg)
            // See if the error has an axios response
            if (isNil(errMsg.response)) {
                if (errMsg.message === 'Network Error') {
                    ntf?.notifyError('Please check your internet connection')
                } else {
                    ntf?.notifyError('An unknown error occured')
                }
                return
            }
            // Axios error message
            const response = errMsg.response
            const errors = response?.data?.errors as ErrorResponse[]
            const hasErrors = isArray(errors) && errors.length > 0

            const SetMessageWithDefault = (message: string) => {
                if (hasErrors) {
                    const fe = first(errors)
                    if(isString(fe)){
                       ntf?.notifyError(fe as string)
                    }
                    else{
                        const { message, property } = fe as ValidationError

                        ntf?.notifyError(
                            'Please verify your ' + defaultTo(property, 'form'),
                            message
                        )
                    }
                  
                } else {
                    ntf?.notifyError(defaultTo(response?.data?.result, message))
                }
            }

            switch (response.status) {
                case 200:
                    SetMessageWithDefault('')
                    break
                case 400:
                    SetMessageWithDefault('Bad Request')
                    break
                case 422:
                    SetMessageWithDefault('The server did not accept the request')
                    break
                case 401:
                    SetMessageWithDefault('You are not logged in.')
                    break
                case 403:
                    SetMessageWithDefault('Please clear you cookies/cache and try again')
                    break
                case 404:
                    SetMessageWithDefault('The requested resource was not found')
                    break
                case 409:
                    SetMessageWithDefault('Please clear you cookies/cache and try again')
                    break
                case 410:
                    SetMessageWithDefault('The requested resource has expired')
                    break
                case 423:
                    SetMessageWithDefault('The requested resource is locked')
                    break
                case 429:
                    SetMessageWithDefault('You have made too many requests, please try again later')
                    break
                case 500:
                    SetMessageWithDefault('There was an error processing your request')
                    break
                default:
                    SetMessageWithDefault('An unknown error occured')
                    break
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
