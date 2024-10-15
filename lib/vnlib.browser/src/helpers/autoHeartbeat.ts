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

import { isRef, type Ref } from "vue";
import { useIntervalFn, syncRef, get, type MaybeRef } from "@vueuse/core";
import { useAccount } from "../account";
import { useSession } from "../session";

export interface IAutoHeartbeatControls {
    /**
     * The current state of the heartbeat interval
     */
    enabled: Ref<boolean>;
    /**
     * Enables the hearbeat interval if configured
     */
    enable: () => void;
    /**
     * Disables the heartbeat interval
     */
    disable: () => void;
}

/**
* Configures shared controls for the heartbeat interval
* @param enabled The a reactive value that may be used to enable/disable the heartbeat interval
*/
export const useAutoHeartbeat = (interval: Readonly<MaybeRef<number>>, enabled: MaybeRef<boolean>): IAutoHeartbeatControls =>{

    //Get heartbeat method to invoke when the timer fires
    const { heartbeat } = useAccount();
    const { isLoggedIn } = useSession();

    //Setup the automatic heartbeat interval
    const { isActive, pause, resume } = useIntervalFn(async () => (await isLoggedIn()) ? heartbeat() : null, interval);

    //Sync the enabled ref with the active state if it is a ref
    if(isRef(enabled)){
        //only sync from caller value to ref
        syncRef(enabled, isActive, { direction: 'ltr' })
    }
    
    //Update timer immediately
    get(enabled) ? resume() : pause();

    return { enabled:isActive, enable:resume, disable:pause }
}