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

/**
 * Represents a uniform message from the server
 */
export interface WebMessage<T = unknown> {
    /**
     * The result of the operation, or an error message
     * if the sucess value is false
     */
    readonly result : T | string;
    /**
     * True if the operation was successful, false otherwise
     */
    readonly success : boolean;
    /**
     * Validation errors, if any occured
     */
    readonly errors?: ServerValidationError[]

    /**
     * Returns the result, or throws an error if the operation was not successful
     */
    getResultOrThrow() : T;
}

/**
 * Represents a validation error from the server for a specific property
 */
export interface ServerValidationError{
    /**
     * The property that failed validation
     */
    readonly property : string;
    /**
     * The error message
     */
    readonly message: string;
}