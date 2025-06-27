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

import { defaultsDeep, mapValues, memoize, get as getAt, set as setAt } from 'lodash-es';
import { manualComputed, type ReadonlyManualRef } from './manualComputed';
import type { GlobalApiConfig } from '../types'

export type AsyncStorageItem<T> = {
    [K in keyof T]: {
        /**
         * Gets the stored value of the slot asynchonously if necessary
         * @returns The value of the slot
         */
        get: () => Promise<T[K]>;
        /**
         * Sets the value of the slot
         * @param value The value to set the slot to
         */
        set: (value: T[K]) => Promise<void>;
    };
};

/**
 * Creates a context-persistent storage slot that can be used to store
 * and retrieve values asynchronously.
 */
export const useStorageSlot = <T extends object>(
    globalState: ReadonlyManualRef<Pick<GlobalApiConfig, 'storage'>>, 
    key: string, 
    defaultValue: T
): AsyncStorageItem<T> => {

    const backend = manualComputed(() => globalState.get('storage'));

    const writeObj = (value: T) => {
        const val = JSON.stringify(value);
        return backend.get()?.setItem(key, val);
    }

    const readObj = async (): Promise<T> => {
        const val = await backend.get()?.getItem(key);
        const obj = JSON.parse(val || '{}');
        return defaultsDeep(obj, defaultValue);
    }

    const storage = memoize(readObj);

    const clearCache = () => {
        if (storage.cache.clear) {
            storage.cache.clear();
        }
    }

    return mapValues<T>(defaultValue, (_val: unknown, key: string) => {

        const get = async (): Promise<any> => {
            const stored = await storage()
            return getAt(stored, key) as any;
        }

        const set = async (value: unknown): Promise<void> => {
            const stored = await storage();
            setAt<T>(stored, key, value);

            //Write localstorage
            await writeObj(stored);

            clearCache();
        }

        return { get, set }
    }) as unknown as AsyncStorageItem<T>;
}
