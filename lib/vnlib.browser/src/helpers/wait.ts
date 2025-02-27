// Copyright (c) 2024 Vaughn Nugent
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

import { set } from "@vueuse/core";
import { readonly, ref, type Ref } from "vue";

export interface IWaitSingal{
    /**
     * The waiting flag ref (readonly)
     */
    readonly waiting: Readonly<Ref<boolean>>;
    /**
     * Sets the waiting flag to the value passed in
     * @param waiting The value to set the waiting flag to
     */
    setWaiting(waiting: boolean): void;
}

const wait = (waiting: Ref<boolean>) : IWaitSingal => {
    return{
        waiting: readonly(waiting),
        setWaiting: (w: boolean) => set(waiting, w)
    }
}

export const useWait = (() => {
    const waiting = ref(false)
    /**
     * Uses the internal waiting flag to determine if the component should be waiting
     * based on pending apiCall() requests.  
     * @returns {Object} { waiting: Boolean, setWaiting: Function }
     * @example //Waiting flag is reactive
     * const { waiting, setWaiting } = useWait()
     * setWaiting(true) //Manually set the waiting flag
     * setWaiting(false) //Manually clear the waiting flag
     */
    return (): IWaitSingal => wait(waiting);
})()

