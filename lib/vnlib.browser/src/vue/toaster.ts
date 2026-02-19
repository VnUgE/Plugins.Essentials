
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

/**
 * Represents a toast notification with title and optional message/description.
 */
export interface ToastMessage {
    title: string;
    message?: string;
}

/**
 * Core toast notification levels matching common toast library patterns.
 */
export type ToastType = 'success' | 'error' | 'info' | 'warning';

/**
 * Adapter interface for integrating any toast notification library.
 * Implement this interface to connect your preferred toast library
 * (e.g., vue-toastification, react-toastify, notyf, etc.)
 */
export interface ToastAdapter {
    /**
     * Show a toast notification with the given type and message.
     * @param type - The notification level (success, error, info, warning)
     * @param message - The notification content (title and optional message)
     * @returns Optional ID string for closing specific toasts
     */
    show(type: ToastType, message: ToastMessage): string | void;

    /**
     * Close a specific toast by ID, or all toasts if no ID provided.
     * @param id - Optional toast ID to close specific notification
     */
    close(id?: string): void;
}

/**
 * Unified toaster API that works with any toast library via adapter pattern.
 * Provides consistent interface for success, error, info, and warning notifications.
 */
export interface Toaster {
    /**
     * Show a success notification.
     * @param title - Success message title
     * @param message - Optional detailed message
     */
    success(title: string, message?: string): void;

    /**
     * Show an error notification.
     * @param title - Error message title
     * @param message - Optional detailed error description
     */
    error(title: string, message?: string): void;

    /**
     * Show an info notification.
     * @param title - Info message title
     * @param message - Optional detailed information
     */
    info(title: string, message?: string): void;

    /**
     * Show a warning notification.
     * @param title - Warning message title
     * @param message - Optional detailed warning
     */
    warning(title: string, message?: string): void;

    /**
     * Close a specific notification or all notifications.
     * @param id - Optional notification ID
     */
    close(id?: string): void;
}

/**
 * Creates a unified toaster instance from any toast library adapter.
 * This allows utilities like useApiCall to work with any toast notification library.
 * 
 * @example
 * ```typescript
 * // Using vue-toastification
 * import { useToast } from 'vue-toastification';
 * 
 * const vueToast = useToast();
 * const adapter: ToastAdapter = {
 *   show: (type, { title, message }) => {
 *     vueToast[type](`${title}${message ? ': ' + message : ''}`);
 *   },
 *   close: (id) => vueToast.clear(id)
 * };
 * 
 * const toaster = createToaster(adapter);
 * toaster.error('Failed to save', 'Please check your input');
 * ```
 * 
 * @example
 * ```typescript
 * // Using console (for testing/development)
 * const consoleAdapter: ToastAdapter = {
 *   show: (type, { title, message }) => {
 *     console[type === 'error' ? 'error' : 'log'](`[${type}] ${title}${message ? ': ' + message : ''}`);
 *   },
 *   close: () => console.log('Closing toast')
 * };
 * 
 * const toaster = createToaster(consoleAdapter);
 * ```
 * 
 * @param adapter - Toast library adapter implementation
 * @returns Unified toaster interface
 */
export const createToaster = (adapter: ToastAdapter): Toaster => {
    const show = (type: ToastType, title: string, message?: string): void => {
        adapter.show(type, { title, message });
    };

    return {
        success: (title, message) => show('success', title, message),
        error: (title, message) => show('error', title, message),
        info: (title, message) => show('info', title, message),
        warning: (title, message) => show('warning', title, message),
        close: (id) => adapter.close(id)
    };
};