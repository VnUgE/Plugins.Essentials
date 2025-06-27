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

import { get as getAt, isEqual } from 'lodash-es';

export interface ReadonlyManualRef<T> {
    /**
     * Gets the value of the manual ref.
     */
    get(): T;
    /**
     * Gets a specific property from the manual ref.
     * @param propName The property name to get from the manual ref.
     */
    get<K extends keyof T>(propName: K): T[K]; 
    /**
     * Checks if the value of the manual ref has changed since the last call to get.
     * @returns True if the value has changed, false otherwise.
     * This operation requires calling get() first to update the cached value. 
     */
    changed(): boolean;
}

export const manualComputed = <T extends object>(getter: () => T): ReadonlyManualRef<T>=> {
    
    let lastValue: T | undefined = undefined;

    const get = <K extends keyof T>(propName?: K): T | T[K] => {
        //Get an update the cached value
        lastValue = getter();
      
        return propName 
          ? getAt(lastValue, propName) 
          : lastValue;
    }

    //Create a new manual ref that will update the cached value
    const changed = () => {
        const latest = getter();
        return isEqual(lastValue, latest);
    }

    return { get, changed }
}
