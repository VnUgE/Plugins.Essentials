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

import { ref, type Ref } from 'vue';
import { defer, isEqual } from 'lodash-es';
import { watchDebounced, type StorageLike } from '@vueuse/core'

export interface ReactiveStorageLike extends StorageLike {
    onStorageChanged: (key: string, callback: () => void) => void;
}

export const toReactive = (storage: Ref<StorageLike | undefined>): ReactiveStorageLike => {

    const getItem = (key: string): string | null => storage.value?.getItem(key) ?? null;
    const setItem = (key: string, value: string): void => storage.value?.setItem(key, value);
    const removeItem = (key: string): void => storage.value?.removeItem(key);

    const onStorageChanged = (key: string, callback: () => void) => {
        //Listen for storage changes on the window and invoke the callback for all changes
        window?.addEventListener('storage', ev => ev.key === key ? callback() : null);

        //Also register watcher for storage change events
        watchDebounced(storage, callback, { debounce: 100, immediate:false })

        //intial update
        callback();
    }

    return {
        getItem,
        setItem,
        removeItem,
        onStorageChanged
    }
}

export const createStorageRef = <T>(backend: ReactiveStorageLike, key: string, defaultValue: T): Ref<T> => {
    //reactive storage element
    const storage = ref<T>(defaultValue);

    //Recovers data from storage
    const onUpdate = () => {
        const string = backend.getItem(key);
        storage.value = JSON.parse(string || "{}");
    }

    //Watch storage changes
    backend.onStorageChanged(key, onUpdate);

    //Watch for reactive changes and write to storage
    watchDebounced(storage, (value) => defer(() => {
        //Convert to string and store
        const string = JSON.stringify(value);
        const oldValue = backend.getItem(key);
        //Only write if the value has changed
        if (isEqual(string, oldValue)) {
            return;
        }
        //Write to storage
        backend.setItem(key, string);
    }), { deep: true, debounce: 100 })

    return storage as Ref<T>;
}
