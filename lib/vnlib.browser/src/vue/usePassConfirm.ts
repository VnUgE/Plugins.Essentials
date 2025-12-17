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

import { useConfirmDialog } from "@vueuse/core";
import { useApiCall, type UseApiCallArgs } from "../vue/useApiCall";
import { AxiosError } from "axios";
import { isEqual, isNil, memoize } from "lodash-es";

/**
 * Extended API pass-through interface for password-protected operations.
 * Includes the user-provided password for elevated access.
 */
export interface IElevatedCallPassThrough  {
    readonly password: string;
}

/**
 * Configuration for password-protected API calls.
 * Extends UseApiCallArgs with a confirm dialog instance.
 * @template T - Type of data returned from the confirm dialog
 */
export interface UsePassConfirmArgs<T> extends UseApiCallArgs {
    readonly dialog: ReturnType<typeof useConfirmDialog<T>>
}

/**
 * Gets the shared password prompt object and the elevated api call method handler 
 * to allow for elevated api calls that require a password.
 * @param args - Configuration object containing toaster for notifications
 * @returns {Object} The password prompt configuration object, and the elevated api call method
 */
export const usePassConfirm = <T>(args: UsePassConfirmArgs<T>) => {

    const apiCall = useApiCall(args); 

    /**
     * Displays the password prompt and executes the api call with the password
     * captured from the prompt. If the api call returns a 401 error, the password
     * prompt is re-displayed and the server error message is displayed.
     * @template TResult - The return type of the elevated API call
     * @param callback - The async callback method that invokes the elevated api call
     * @returns A promise that resolves to the result of the async function, or undefined if canceled
     */
    const elevatedApiCall = <TResult>(callback: (api: IElevatedCallPassThrough) => Promise<TResult>): Promise<TResult | undefined> => {
        //Invoke api call method but handle 401 errors by re-displaying the password prompt
        return apiCall<TResult>(async () : Promise<TResult | undefined> => {
            // eslint-disable-next-line no-constant-condition
            while (1) {

                //Display the password prompt
                const { data, isCanceled } = await args.dialog.reveal()
                
                if (isCanceled) {
                    break;
                }

                try {
                    //Execute the api call with prompt response
                    return await callback({ ...data });
                }
                //Catch 401 errors and re-display the password prompt, otherwise throw the error
                catch (err) {
                    if(!(err instanceof AxiosError)){
                       throw err;
                    }

                    const { response } = err;

                    if(isNil(response)){
                        throw err;
                    }

                    //Check status code, if 401, re-display the password prompt
                    if (!isEqual(response?.status, 401)) {
                        throw err;
                    } 

                    //Display the error message
                    args.toaster.error(response.data.result);

                    //Re-display the password prompt
                }
            }
        })
    }

    //Pass through confirm object and elevated api call
    return { ...args.dialog, ...apiCall, elevatedApiCall };
};