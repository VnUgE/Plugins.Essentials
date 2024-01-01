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

import { defer, isEqual } from 'lodash-es'
import { computed, ref, type Ref } from 'vue'
import Cookies from 'universal-cookie'

export interface CookieMonitor<T> {
    readonly cookieValue: Readonly<Ref<T>>;
    readonly enabled: Readonly<Ref<boolean>>;
}

export type CookieValueConveter<T> = (value: string) => T;

/**
 * Creates a reactive wrapper that monitors a single cookie value for changes
 * @param enabled A ref that indicates if the cookie should be monitored
 * @param cookieName The name of the cookie to monitor
 * @param converter An optional converter function to convert the cookie value to a different type 
 */
export const createCookieMonitor = <T = string>(enabled: Ref<boolean>, cookieName: Ref<string | undefined>, converter?: CookieValueConveter<T>) : CookieMonitor<T> => {

    //Set default converter
    converter ??= (value: string) => value as unknown as T;

    const cookieJar = new Cookies();
    const cookieRef = ref<string>('');
    const cookieValue = computed<T>(() => converter!(cookieRef.value));
    
    //Store last value to avoid unnecessary updates
    let lastValue = '';

    const get = (): string => cookieJar.get<string>(cookieName.value || '', { doNotParse: true });

    const checkAndUpdateCookie = () => {
        if (!enabled.value) {
            return;
        }
        //Get the new cookeie value
        const newValue = get()
        if (!isEqual(newValue, lastValue)) {
            lastValue = cookieRef.value = newValue
        }
    }

    //Watch for changes to the cookie and update the ref only if its enabled
    cookieJar.addChangeListener(() => defer(checkAndUpdateCookie))

    //Initial cookie check
    checkAndUpdateCookie()

    return { cookieValue , enabled }
}