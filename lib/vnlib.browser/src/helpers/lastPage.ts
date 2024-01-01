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

import { defaultTo } from "lodash-es";
import { useRouter } from "vue-router"

export interface ILastPage{
    /**
     * Pushes the current page into the last-page stack
     */
    push(): void;
    /**
    * Stores the current page and navigates to the desired route
    * @param route The route to navigate to
    */
    pushAndNavigate(route: object): void;
    /**
     * Navigates to the last page if it exists
     */
    gotoLastPage(): void;
}

export interface ILastPageStorage {

    /**
     * Pushes the current page into the last-page stack
     */
    push(route: string): void;

    /**
     * Pops the last page from the last-page stack storage
     * @returns {any} The last page route object stored
     */
    pop(): string | null;
}

const storageKey = "lastPage";

//Storage impl
const defaultStack = (): ILastPageStorage => {
    const storage = sessionStorage;

    const push = (route: string) => {
        //Serialize the route data and store it
        storage?.setItem(storageKey, route);
    }

    const pop = (): string | null => {
        //Get the route data and deserialize it
        const route = storage?.getItem(storageKey);
        if (route) {
            storage?.removeItem(storageKey);
            return route;
        }
        return null;
    }
    return { push, pop }
}

/**
 * Gets the configuration for the last page the user was on 
 * when the page guard was called. This is used to return to the
 * last page after login.
 * @returns { gotoLastPage: Function }
 */
export const useLastPage = (storage?: ILastPageStorage): ILastPage => {
    
    //fallback to default storage
    const _storage = defaultTo(storage, defaultStack());

    //Get the current router instance
    const router = useRouter();

    //Store the current page to the last page stack
    const push = () => _storage.push(router.currentRoute.value.fullPath);

    const pushAndNavigate = (route: object) => {
        //Store the current page to the last page stack
        push();
        //Navigate to the desired route
        router.push(route);
    };

    const gotoLastPage = () => {
        //Get the last stored page and navigate to it
        const lp = _storage.pop();
        if (lp) {
            router.push(lp);
        }
    };

    return { push, pushAndNavigate, gotoLastPage }
}