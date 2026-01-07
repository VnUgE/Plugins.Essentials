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
 * Pass-through payload for password-protected operations.
 * Carries the user-supplied password from the confirmation dialog.
 */
export interface IElevatedCallPassThrough  {
    readonly password: string;
}

/**
 * Configuration for password-protected API calls, including the confirm dialog instance.
 * @template T - Dialog data type captured from the prompt.
 */
export interface UsePassConfirmArgs<T> extends UseApiCallArgs {
    readonly dialog: ReturnType<typeof useConfirmDialog<T>>
}

/**
 * Builds a password confirmation prompt with retry-aware API execution.
 * @param args - Toaster and confirm dialog instances used by the prompt flow.
 * @returns Combined dialog helpers plus `elevatedApiCall` for protected operations.
 */
export const usePassConfirm = <T>(args: UsePassConfirmArgs<T>) => {

    const apiCall = useApiCall(args); 

    /**
     * Prompts for a password, executes the protected call, and retries on 401.
     * @template TResult - Return type of the protected API call.
     * @param callback - Async callback that receives the captured password.
     * @returns Result of the protected call, or undefined when canceled.
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