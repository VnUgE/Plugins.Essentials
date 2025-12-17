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

import {
    attempt,
    defaultsDeep,
    defaultTo,
    get as getAt,
    isError,
    isFunction,
    mapValues,
    memoize,
    set as setAt
} from 'lodash-es';
import type { StorageLikeAsync } from '../types';

/**
 * Projects each property of the supplied type into an async getter/setter pair.
 */
export type AsyncStorageItem<T> = {
    [K in keyof T]: {
        /**
         * Gets the stored value of the slot asynchronously if necessary
         */
        get: () => Promise<T[K]>;
        /**
         * Persists the supplied value for the slot
         */
        set: (value: T[K]) => Promise<void>;
    };
};


/**
 * Projects an object model onto the configured async storage provider where
 * each property exposes typed async getters/setters.
 */
export const createStorageSlot = <T extends object>(
    storage: StorageLikeAsync,
    key: string,
    defaultValue: T
): AsyncStorageItem<T> => {

    const writeObj = async (value: T): Promise<void> => {
        const serialized = JSON.stringify(value);
        await storage.setItem(key, serialized);
    }

    const parseStoredValue = (raw: string | null | undefined): object => {
        const parsed = attempt(JSON.parse, defaultTo(raw, '{}'));
        return isError(parsed) ? {} : parsed;
    }

    const readObj = async (): Promise<T> => {
        const storedValue = await storage.getItem(key);
        const parsedValue = parseStoredValue(storedValue) as Partial<T>;
        return defaultsDeep(parsedValue, defaultValue);
    }

    // memoize() gives us a single outstanding read promise per slot key
    const getSnapshot = memoize(readObj);

    const clearCache = (): void => {
        const cache = getSnapshot.cache as Map<unknown, Promise<T>> & { clear?: () => void };

        if (isFunction(cache.clear))
        {
            cache.clear();
            return;
        }

        // Memoize cache falls back to Map, so deleting the single key is sufficient
        cache.delete(undefined);
    }

    return mapValues(defaultValue, (_val: unknown, slotKey: string) => {

        const get = async (): Promise<any> => {
            const stored = await getSnapshot();
            return getAt(stored, slotKey);
        }

        const set = async (value: unknown): Promise<void> => {
            const stored = await getSnapshot();
            setAt(stored, slotKey, value);

            await writeObj(stored);
            clearCache();
        }

        return { get, set };
    }) as AsyncStorageItem<T>;
}
