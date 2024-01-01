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

import { watch } from 'vue'
import { useSession } from "../session";
import { useLastPage } from './lastPage';
import type { ILastPageStorage } from "./lastPage";


/** 
 * When called, configures the component to 
 * only be visible when the user is logged in. If the user is 
 * not logged in, the user is redirected to the login page. 
 * @remarks Once called, if the user is logged-in changes will be
 * watch to redirect if the user becomes logged out.
*/
export const usePageGuard = (loginRoute = { name: 'Login' }, lpStorage?: ILastPageStorage): void => {
    //Get the session state
    const session = useSession();

    //Get last page controller, fall back to default session storage stack
    const { pushAndNavigate } = useLastPage(lpStorage)

    // Initial check for logged in to guard the page
    if (!session.loggedIn.value) {
        //Store last route and redirect to login
        pushAndNavigate(loginRoute);
    }

    // setup watcher on session login value
    // If the login value changes to false, redirect to login page
    watch(session.loggedIn, value => value === false ? pushAndNavigate(loginRoute) : null)
}
