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

import { defaultsDeep, mapValues, memoize, get as getAt, set as setAt, isEqual } from 'lodash-es';
import { getGlobalStateInternal } from './globalState/index'

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



export interface ReadonlyManualRef<T> {
    get(): T;
    get<K extends keyof T>(propName: K): T[K]; 
    changed(): boolean;
}

export const manualComputed = <T extends object>(getter: () => T): ReadonlyManualRef<T>=> {
    
    let lastValue: T | undefined = undefined;

    return {
        get: <K extends keyof T>(propName?: K): T | T[K] => {
            //Get an update the cached value
            lastValue = getter();
          
            return propName 
              ? getAt(lastValue, propName) 
              : lastValue;
        },
        changed: () => {
            const latest = getter();
            return isEqual(lastValue, latest);
        }
    }
}

export const createStorageSlot = <T extends object>(key: string, defaultValue: T): AsyncStorageItem<T> => {

    const config = getGlobalStateInternal()
    const backend = manualComputed(() => config.get('storage'));

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
