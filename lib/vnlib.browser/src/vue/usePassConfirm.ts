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
import { 
    type IApiPassThrough, 
    useApiCall, 
    UseApiCallArgs 
} from "../vue/useApiCall";
import { AxiosError } from "axios";
import { isEqual, isNil, memoize } from "lodash-es";

export interface IElevatedCallPassThrough extends IApiPassThrough {
    readonly password: string;
}

//Must store a global reference to the confirm dialog to share between components
const dialog = memoize(useConfirmDialog);

/**
 * Gets the shared password prompt object and the elevated api call method handler 
 * to allow for elevated api calls that require a password.
 * @returns {Object} The password prompt configuration object, and the elevated api call method
 */
export const usePassConfirm = (args?: UseApiCallArgs) => {

    //Shared confirm object
    const confirm = dialog();

    const apiCall = useApiCall(args!);

    /**
     * Displays the password prompt and executes the api call with the password
     * captured from the prompt. If the api call returns a 401 error, the password
     * prompt is re-displayed and the server error message is displayed in the form
     * error toaster.
     * @param callback The async callback method that invokes the elevated api call.
     * @returns A promise that resolves to the result of the async function
     */
    const elevatedApiCall = <T>(callback: (api: IElevatedCallPassThrough) => Promise<T>): Promise<T | undefined> => {
        //Invoke api call method but handle 401 errors by re-displaying the password prompt
        return apiCall<T>(async (api: IApiPassThrough) : Promise<T | undefined> => {
            // eslint-disable-next-line no-constant-condition
            while (1) {

                //Display the password prompt
                const { data, isCanceled } = await confirm.reveal()
                
                if (isCanceled) {
                    break;
                }

                try {
                    //Execute the api call with prompt response
                    return await callback({...api, ...data });
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
                    api.toaster.form.error({ title: response.data.result });

                    //Re-display the password prompt
                }
            }
        })
    }

    //Pass through confirm object and elevated api call
    return { ...confirm, ...apiCall, elevatedApiCall };
};